package netreport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Transfer is one HTTP exchange over a probe connection.
type Transfer struct {
	Status   Status `json:"status"`
	HTTP     int    `json:"http,omitempty"`
	Location string `json:"location,omitempty"`
	// Bytes is the body received; RxBytes everything the server sent on
	// the TCP connection, the TLS handshake included.
	Bytes   int64  `json:"bytes"`
	RxBytes int64  `json:"rxBytes,omitempty"`
	Ms      int64  `json:"ms"`
	KBps    int64  `json:"kbps,omitempty"`
	Geo     bool   `json:"geo,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// The freeze stops a connection after about 25 packets in either
// direction, 14-34 KB of payload depending on packet sizes; anything that
// stalls past maxFreezeBytes is a different problem.
const (
	minFreezeBytes = 8 * 1024
	maxFreezeBytes = 64 * 1024
	bodySampleSize = 64 * 1024
	// slowKBps marks a transfer that completed but crawled.
	slowKBps = 64
)

type deadlineReader struct {
	conn net.Conn
	end  time.Time
}

// Read refreshes the stall deadline on every call, capped by the overall end.
func (r *deadlineReader) Read(b []byte) (int, error) {
	deadline := time.Now().Add(stallTimeout)
	if deadline.After(r.end) {
		deadline = r.end
	}
	_ = r.conn.SetReadDeadline(deadline)
	return r.conn.Read(b)
}

type fetchOptions struct {
	host        string
	path        string
	want        int64
	rangeHeader bool
	geo         *geoMarkers
	// userAgent defaults to a browser's; file servers get a tool's, as
	// some close the connection on a browser asking for a test file.
	userAgent string
}

// fetch sends a GET and reads up to want body bytes. A stream that stops
// mid-body is frozen when it stopped within the TSPU window, stalled
// otherwise.
func fetch(ctx context.Context, conn net.Conn, rx func() int64, options fetchOptions) Transfer {
	start := time.Now()
	end := start.Add(20 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(end) {
		end = deadline
	}
	path := options.path
	if path == "" {
		path = "/"
	}
	agent := options.userAgent
	if agent == "" {
		agent = userAgent
	}
	request := "GET " + path + " HTTP/1.1\r\nHost: " + options.host + "\r\nUser-Agent: " + agent +
		"\r\nAccept: text/html,application/xhtml+xml,application/json,*/*;q=0.8" +
		"\r\nAccept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\nAccept-Encoding: identity\r\n"
	if options.rangeHeader {
		request += fmt.Sprintf("Range: bytes=0-%d\r\n", options.want-1)
	}
	request += "Connection: close\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(stallTimeout))
	if _, err := io.WriteString(conn, request); err != nil {
		return Transfer{Status: classify(err), Ms: since(start), Detail: detail(err)}
	}
	reader := bufio.NewReaderSize(&deadlineReader{conn: conn, end: end}, 16*1024)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		transfer := Transfer{Status: classify(err), Ms: since(start), RxBytes: rx(), Detail: detail(err)}
		transfer.Status = frozenOr(transfer.Status, transfer.RxBytes)
		return transfer
	}
	defer response.Body.Close()
	transfer := Transfer{HTTP: response.StatusCode, Location: shortLocation(response.Header.Get("Location"))}
	sample := make([]byte, 0, bodySampleSize)
	buffer := make([]byte, 32*1024)
	var readErr error
	firstByte := time.Time{}
	for transfer.Bytes < options.want {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			if firstByte.IsZero() {
				firstByte = time.Now()
			}
			if room := bodySampleSize - len(sample); room > 0 {
				sample = append(sample, buffer[:min(n, room)]...)
			}
			transfer.Bytes += int64(n)
		}
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
		if ctx.Err() != nil {
			readErr = ctx.Err()
			break
		}
	}
	transfer.Ms = since(start)
	transfer.RxBytes = rx()
	if !firstByte.IsZero() {
		if elapsed := time.Since(firstByte).Seconds(); elapsed > 0.01 && transfer.Bytes > 32*1024 {
			transfer.KBps = int64(float64(transfer.Bytes) / 1024 / elapsed)
		}
	}
	transfer.Geo = options.geo.match(response, sample)
	switch {
	case readErr != nil:
		transfer.Status = frozenOr(classify(readErr), transfer.RxBytes)
		transfer.Detail = detail(readErr)
	case transfer.Bytes >= 128*1024 && transfer.KBps > 0 && transfer.KBps < slowKBps:
		transfer.Status = StatusSlow
	default:
		transfer.Status = StatusOK
	}
	return transfer
}

func frozenOr(status Status, rx int64) Status {
	if status != StatusTimeout {
		return status
	}
	if rx >= minFreezeBytes && rx < maxFreezeBytes {
		return StatusFrozen
	}
	if rx > 0 {
		return StatusStalled
	}
	return StatusTimeout
}

func (g *geoMarkers) match(response *http.Response, sample []byte) bool {
	if g == nil {
		return false
	}
	if len(g.Status) > 0 {
		matched := false
		for _, status := range g.Status {
			matched = matched || status == response.StatusCode
		}
		if !matched {
			return false
		}
		if len(g.Body) == 0 && len(g.Location) == 0 {
			return true
		}
	}
	location := response.Header.Get("Location")
	for _, marker := range g.Location {
		if strings.Contains(location, marker) {
			return true
		}
	}
	body := string(sample)
	for _, marker := range g.Body {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// shortLocation keeps a redirect's host and path: enough to recognize a
// block page or a region page, without query strings.
func shortLocation(location string) string {
	if index := strings.IndexAny(location, "?#"); index >= 0 {
		location = location[:index]
	}
	if len(location) > 120 {
		location = location[:120]
	}
	return location
}
