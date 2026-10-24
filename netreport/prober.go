package netreport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/libxray/netbind"
)

const (
	tcpTimeout = 5 * time.Second
	// A ServerHello takes one round trip; DPI drops are silent, so this is
	// what every blocked handshake costs.
	handshakeTimeout = 4 * time.Second
	// stallTimeout ends a transfer whose data stopped arriving. The TSPU
	// freeze never resumes, so a few seconds tell it from a slow server.
	stallTimeout = 4 * time.Second
	userAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	toolAgent    = "curl/8.10.1"
)

// prober holds what every probe of one run shares: the interface binding,
// the catalog and the reference resolver's cache.
type prober struct {
	ctx      context.Context
	control  func(network, address string, conn syscall.RawConn) error
	maxBytes int64
	bypass   bool
	cat      catalog
	http     *http.Client

	mu        sync.Mutex
	lookups   map[string]*lookupEntry
	certs     map[string]Status
	systemDNS []netip.Addr
	passedSNI string
}

type lookupEntry struct {
	done   chan struct{}
	addrs  []netip.Addr
	source string
	err    error
}

func newProber(ctx context.Context, request Request, cat catalog) *prober {
	p := &prober{
		ctx:      ctx,
		control:  netbind.Control(request.Interface),
		maxBytes: clampBytes(request.MaxBytes),
		bypass:   request.Bypass,
		cat:      cat,
		lookups:  map[string]*lookupEntry{},
		certs:    map[string]Status{},
	}
	p.http = &http.Client{
		Transport: &http.Transport{
			// Never the environment's proxy: the report describes the
			// network, not whatever the user routes through.
			Proxy:                 nil,
			DialContext:           p.dialContext,
			TLSHandshakeTimeout:   handshakeTimeout,
			ResponseHeaderTimeout: 8 * time.Second,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       20 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return p
}

func clampBytes(value int64) int64 {
	switch {
	case value <= 0:
		return defaultMaxBytes
	case value < minMaxBytes:
		return minMaxBytes
	case value > maxMaxBytes:
		return maxMaxBytes
	}
	return value
}

func since(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func netFor(ip netip.Addr, base string) string {
	if ip.Unmap().Is4() {
		return base + "4"
	}
	return base + "6"
}

func (p *prober) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: p.control}
}

func (p *prober) dialTCP(ctx context.Context, ip netip.Addr, port int) (net.Conn, Step) {
	start := time.Now()
	address := netip.AddrPortFrom(ip.Unmap(), uint16(port)).String()
	conn, err := p.dialer(tcpTimeout).DialContext(ctx, netFor(ip, "tcp"), address)
	step := Step{Status: classify(err), Ms: since(start)}
	if err != nil {
		step.Detail = detail(err)
		return nil, step
	}
	return conn, step
}

func (p *prober) dialUDP(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	address := netip.AddrPortFrom(ip.Unmap(), uint16(port)).String()
	return p.dialer(tcpTimeout).DialContext(ctx, netFor(ip, "udp"), address)
}

func (p *prober) listenUDP(ctx context.Context, ipv6 bool) (net.PacketConn, error) {
	config := net.ListenConfig{Control: p.control}
	if ipv6 {
		return config.ListenPacket(ctx, "udp6", "[::]:0")
	}
	return config.ListenPacket(ctx, "udp4", "0.0.0.0:0")
}

// dialContext serves the HTTP client: literal addresses dial directly, names
// go through the reference resolver.
func (p *prober) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, _, err = p.lookup(ctx, host); err != nil {
		return nil, err
	}
	var last error
	for index, ip := range addrs {
		if index == 2 {
			break
		}
		if network == "tcp4" && !ip.Is4() || network == "tcp6" && ip.Is4() {
			continue
		}
		conn, step := p.dialTCP(ctx, ip, port)
		if conn != nil {
			return conn, nil
		}
		last = fmt.Errorf("dial %s: %s", host, step.Status)
	}
	if last == nil {
		last = errors.New("no usable address for " + host)
	}
	return nil, last
}

// lookup resolves a name for probing: the first DoH resolver that answers,
// then plain DNS to resolvers the network rarely intercepts, then the
// network's own. The source is reported next to the addresses.
func (p *prober) lookup(ctx context.Context, host string) ([]netip.Addr, string, error) {
	p.mu.Lock()
	entry, found := p.lookups[host]
	if !found {
		entry = &lookupEntry{done: make(chan struct{})}
		p.lookups[host] = entry
	}
	p.mu.Unlock()
	if found {
		select {
		case <-entry.done:
			return entry.addrs, entry.source, entry.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	entry.addrs, entry.source, entry.err = p.resolveReference(ctx, host)
	close(entry.done)
	return entry.addrs, entry.source, entry.err
}

func (p *prober) resolveReference(ctx context.Context, host string) ([]netip.Addr, string, error) {
	for _, resolver := range p.cat.Resolvers {
		if resolver.DoH == "" {
			continue
		}
		answer, err := p.queryDoH(ctx, resolver.DoH, host, dns.TypeA)
		if err == nil && answer.rcode == dns.RcodeSuccess && len(answer.IPs) > 0 {
			return answer.IPs, "doh:" + resolver.ID, nil
		}
		if err == nil && answer.rcode == dns.RcodeNameError {
			return nil, "doh:" + resolver.ID, errors.New("no such host")
		}
	}
	plain := []string{"9.9.9.9", "77.88.8.8"}
	p.mu.Lock()
	for _, server := range p.systemDNS {
		plain = append(plain, server.String())
	}
	p.mu.Unlock()
	for _, server := range plain {
		ip, err := netip.ParseAddr(server)
		if err != nil {
			continue
		}
		answers, err := p.queryUDP(ctx, ip, host, dns.TypeA, 0)
		if err == nil && len(answers) > 0 && answers[0].rcode == dns.RcodeSuccess && len(answers[0].IPs) > 0 {
			return answers[0].IPs, "udp:" + server, nil
		}
	}
	return nil, "", errors.New("unable to resolve " + host)
}

// dnsAnswer is one response; IPs holds A/AAAA records, Text TXT strings.
type dnsAnswer struct {
	Ms     int64        `json:"ms"`
	Rcode  string       `json:"rcode"`
	AA     bool         `json:"aa,omitempty"`
	IPs    []netip.Addr `json:"ips,omitempty"`
	Text   []string     `json:"text,omitempty"`
	rcode  int
	digest string
}

func newQuery(host string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true
	return msg
}

func readAnswer(msg *dns.Msg, ms int64) dnsAnswer {
	answer := dnsAnswer{Ms: ms, rcode: msg.Rcode, Rcode: dns.RcodeToString[msg.Rcode], AA: msg.Authoritative}
	for _, record := range msg.Answer {
		switch value := record.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(value.A); ok {
				answer.IPs = append(answer.IPs, ip.Unmap())
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(value.AAAA); ok {
				answer.IPs = append(answer.IPs, ip)
			}
		case *dns.TXT:
			answer.Text = append(answer.Text, value.Txt...)
		}
	}
	answer.digest = fmt.Sprint(answer.rcode, answer.IPs, answer.Text)
	return answer
}

func (p *prober) queryDoH(ctx context.Context, endpoint, host string, qtype uint16) (dnsAnswer, error) {
	packed, err := newQuery(host, qtype).Pack()
	if err != nil {
		return dnsAnswer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if err != nil {
		return dnsAnswer{}, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	start := time.Now()
	response, err := p.http.Do(request)
	if err != nil {
		return dnsAnswer{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return dnsAnswer{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return dnsAnswer{}, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return dnsAnswer{}, err
	}
	return readAnswer(msg, since(start)), nil
}

// queryUDP sends one query from a fresh socket, as Go's and most stub
// resolvers do, and collects every response with its id for listen after the
// first one: an on-path injector answers first, the real resolver later.
// With listen 0 it returns on the first response.
func (p *prober) queryUDP(ctx context.Context, server netip.Addr, host string, qtype uint16, listen time.Duration) ([]dnsAnswer, error) {
	query := newQuery(host, qtype)
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}
	conn, err := p.dialUDP(ctx, server, 53)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
		return nil, err
	}
	deadline := start.Add(2500 * time.Millisecond)
	var answers []dnsAnswer
	buffer := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return answers, ctx.Err()
		}
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buffer)
		if err != nil {
			if len(answers) > 0 || classify(err) == StatusTimeout {
				return answers, nil
			}
			return answers, err
		}
		msg := new(dns.Msg)
		if msg.Unpack(buffer[:n]) != nil || msg.Id != query.Id {
			continue
		}
		answers = append(answers, readAnswer(msg, since(start)))
		if listen <= 0 || len(answers) >= 4 {
			return answers, nil
		}
		if len(answers) == 1 {
			deadline = time.Now().Add(listen)
		}
	}
}
