package netreport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// classify maps a dial, handshake or read error to what the client saw.
func classify(err error) Status {
	if err == nil {
		return StatusOK
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return StatusTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StatusTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return StatusClosed
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if status := classifyErrno(errno); status != "" {
			return status
		}
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "remote error: tls"), strings.Contains(text, "(remote)"):
		// A TLS alert, or a QUIC error the server sent.
		return StatusAlert
	case strings.Contains(text, "connection reset"), strings.Contains(text, "forcibly closed"):
		return StatusReset
	case strings.Contains(text, "connection refused"):
		return StatusRefused
	case strings.Contains(text, "unreachable"):
		return StatusUnreachable
	}
	return StatusError
}

// detail keeps an error short enough for a report: no addresses, which the
// report holds elsewhere and the App may mask.
func detail(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if index := strings.LastIndex(text, ": "); index >= 0 && index+2 < len(text) {
		text = text[index+2:]
	}
	if len(text) > 80 {
		text = text[:80]
	}
	return text
}

func failed(status Status) bool {
	return status != StatusOK && status != StatusAlert && status != StatusSkipped && status != ""
}

// reached reports whether the other side answered at all: an alert or an
// invalid certificate still proves the path is open.
func reached(status Status) bool {
	return status == StatusOK || status == StatusAlert || status == StatusCertInvalid
}
