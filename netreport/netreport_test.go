package netreport

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func addrs(texts ...string) []netip.Addr {
	var out []netip.Addr
	for _, text := range texts {
		out = append(out, netip.MustParseAddr(text))
	}
	return out
}

func answer(ms int64, rcode int, aa bool, ips ...string) dnsAnswer {
	msg := new(dns.Msg)
	msg.Rcode = rcode
	msg.Authoritative = aa
	for _, ip := range ips {
		msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP(ip)})
	}
	return readAnswer(msg, ms)
}

func TestJudgeName(t *testing.T) {
	p := newProber(context.Background(), Request{}, catalog{})
	reference := addrs("104.21.32.39", "172.67.182.196")
	cases := []struct {
		name    string
		answers []dnsAnswer
		want    Status
	}{
		{"no answer", nil, StatusTimeout},
		{"same addresses", []dnsAnswer{answer(40, dns.RcodeSuccess, false, "172.67.182.196")}, StatusOK},
		// ER-Telecom: a stub twice within 2 ms, then the resolver's answer.
		{"injected", []dnsAnswer{
			answer(2, dns.RcodeSuccess, false, "188.186.146.208"),
			answer(2, dns.RcodeSuccess, false, "188.186.146.208"),
			answer(55, dns.RcodeSuccess, false, "172.67.182.196", "104.21.32.39"),
		}, StatusInjected},
		// MegaFon: one authoritative NXDOMAIN in place of 8.8.8.8's answer.
		{"forged nxdomain", []dnsAnswer{answer(21, dns.RcodeNameError, true)}, StatusNXDomain},
		{"no records", []dnsAnswer{answer(21, dns.RcodeSuccess, false)}, StatusEmpty},
		{"private stub", []dnsAnswer{answer(21, dns.RcodeSuccess, false, "10.10.34.35")}, StatusSpoofed},
	}
	for _, test := range cases {
		if got := p.judgeName(context.Background(), "rutracker.org", test.answers, reference); got != test.want {
			t.Errorf("%s: got %s, want %s", test.name, got, test.want)
		}
	}
	// Without a reference only a forged-looking NXDOMAIN is judged.
	if got := p.judgeName(context.Background(), "x", []dnsAnswer{answer(5, dns.RcodeNameError, true)}, nil); got != StatusNXDomain {
		t.Errorf("unreferenced forged nxdomain: got %s", got)
	}
	if got := p.judgeName(context.Background(), "x", []dnsAnswer{answer(5, dns.RcodeNameError, false)}, nil); got != StatusOK {
		t.Errorf("unreferenced honest nxdomain: got %s", got)
	}
}

func TestFrozenOr(t *testing.T) {
	cases := []struct {
		status Status
		rx     int64
		want   Status
	}{
		{StatusTimeout, 0, StatusTimeout},
		{StatusTimeout, 4 * 1024, StatusStalled},
		{StatusTimeout, 16 * 1024, StatusFrozen},
		{StatusTimeout, 200 * 1024, StatusStalled},
		{StatusReset, 16 * 1024, StatusReset},
	}
	for _, test := range cases {
		if got := frozenOr(test.status, test.rx); got != test.want {
			t.Errorf("frozenOr(%s, %d) = %s, want %s", test.status, test.rx, got, test.want)
		}
	}
}

func TestTLSFailure(t *testing.T) {
	ok, timeout, alert := &Step{Status: StatusOK}, &Step{Status: StatusTimeout}, &Step{Status: StatusAlert}
	cases := []struct {
		noSNI, random, white *Step
		want                 Status
	}{
		{ok, alert, nil, StatusSNIBlocked},
		{ok, timeout, ok, StatusSNIWhitelist},
		{ok, timeout, timeout, StatusNoSNIOnly},
		{timeout, timeout, timeout, StatusTLSBlocked},
		{nil, nil, nil, StatusTLSBlocked},
	}
	for index, test := range cases {
		if got := tlsFailure(test.noSNI, test.random, test.white); got != test.want {
			t.Errorf("case %d: got %s, want %s", index, got, test.want)
		}
	}
}

func TestMappedPort(t *testing.T) {
	response := make([]byte, 32)
	response[0], response[1] = 0x01, 0x01
	// XOR-MAPPED-ADDRESS, length 8, family IPv4, port 54321 ^ 0x2112.
	copy(response[20:], []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01})
	port := uint16(54321) ^ 0x2112
	response[26], response[27] = byte(port>>8), byte(port)
	got, err := mappedPort(response)
	if err != nil || got != 54321 {
		t.Fatalf("mappedPort = %d, %v", got, err)
	}
	if _, err := mappedPort(response[:20]); err == nil {
		t.Fatal("a response without attributes has no mapped port")
	}
}

func TestCymruParsing(t *testing.T) {
	if got := cymruOriginName(netip.MustParseAddr("31.173.83.237")); got != "237.83.173.31.origin.asn.cymru.com" {
		t.Errorf("IPv4 name %q", got)
	}
	if got := cymruOriginName(netip.MustParseAddr("2a03:d000::1")); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, ".0.0.0.d.3.0.a.2.origin6.asn.cymru.com") {
		t.Errorf("IPv6 name %q", got)
	}
	info, err := parseCymruOrigin("25159 13238 | 31.173.80.0/21 | RU | ripencc | 2011-04-04")
	if err != nil || info.ASN != 25159 || info.Prefix != "31.173.80.0/21" || info.Country != "RU" {
		t.Errorf("origin %+v, %v", info, err)
	}
	if _, err := parseCymruOrigin(" | 1.2.3.0/24"); err == nil {
		t.Error("an empty origin parsed")
	}
	if got := parseCymruHolder("25159 | RU | ripencc | 2002-08-13 | SONICDUO-AS - PJSC MegaFon, RU"); got != "SONICDUO-AS - PJSC MegaFon, RU" {
		t.Errorf("holder %q", got)
	}
	if got := parseCymruHolder("31363 | RU | ripencc | 2002-08-13 | MOSCOW-AS - JSC _ER-Telecom Holding_, RU"); got != `MOSCOW-AS - JSC "ER-Telecom Holding", RU` {
		t.Errorf("quoted holder %q", got)
	}
}

// freezingListener stops writing to every accepted connection after limit
// bytes, as the TSPU does, and holds it open.
type freezingListener struct {
	net.Listener
	limit int
}

func (l freezingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &freezingConn{Conn: conn, left: l.limit, closed: make(chan struct{})}, nil
}

type freezingConn struct {
	net.Conn
	left   int
	closed chan struct{}
	once   sync.Once
}

// Write passes limit bytes, then blocks until the connection is closed.
func (c *freezingConn) Write(b []byte) (int, error) {
	if c.left <= 0 {
		<-c.closed
		return 0, net.ErrClosed
	}
	if len(b) > c.left {
		n, _ := c.Conn.Write(b[:c.left])
		c.left = 0
		<-c.closed
		return n, net.ErrClosed
	}
	c.left -= len(b)
	return c.Conn.Write(b)
}

func (c *freezingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func blobServer(t *testing.T, limit int) *httptest.Server {
	t.Helper()
	body := strings.Repeat("x", 512*1024)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/geo" {
			w.Header().Set("Location", "https://example.com/app-unavailable-in-region")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	if limit > 0 {
		server.Listener = freezingListener{Listener: server.Listener, limit: limit}
	}
	server.StartTLS()
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	return server
}

func dialBlob(t *testing.T, server *httptest.Server) (*tls.Conn, *countingConn) {
	t.Helper()
	raw, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	counter := &countingConn{Conn: raw}
	conn := tls.Client(counter, &tls.Config{InsecureSkipVerify: true})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, counter
}

func TestFetchCompletes(t *testing.T) {
	conn, counter := dialBlob(t, blobServer(t, 0))
	transfer := fetch(context.Background(), conn, counter.rx.Load, fetchOptions{host: "blob", want: 256 * 1024})
	if transfer.Status != StatusOK || transfer.HTTP != 200 || transfer.Bytes != 256*1024 {
		t.Fatalf("transfer %+v", transfer)
	}
}

func TestFetchFrozen(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the stall timeout")
	}
	conn, counter := dialBlob(t, blobServer(t, 18*1024))
	transfer := fetch(context.Background(), conn, counter.rx.Load, fetchOptions{host: "blob", want: 256 * 1024})
	if transfer.Status != StatusFrozen {
		t.Fatalf("transfer %+v, want frozen", transfer)
	}
	if transfer.RxBytes < minFreezeBytes || transfer.RxBytes >= maxFreezeBytes {
		t.Fatalf("frozen at %d bytes", transfer.RxBytes)
	}
}

func TestFetchGeoMarker(t *testing.T) {
	conn, counter := dialBlob(t, blobServer(t, 0))
	transfer := fetch(context.Background(), conn, counter.rx.Load, fetchOptions{
		host: "blob", path: "/geo", want: 64 * 1024,
		geo: &geoMarkers{Location: []string{"app-unavailable-in-region"}},
	})
	if !transfer.Geo || transfer.HTTP != http.StatusFound || transfer.Location != "https://example.com/app-unavailable-in-region" {
		t.Fatalf("transfer %+v", transfer)
	}
}

func TestSiteVerdict(t *testing.T) {
	ok := Step{Status: StatusOK}
	cases := []struct {
		name   string
		result SiteResult
		want   Status
	}{
		{"tcp", SiteResult{TCP: Step{Status: StatusTimeout}}, StatusIPBlocked},
		{"cert", SiteResult{TCP: ok, TLS: Step{Status: StatusCertInvalid}}, StatusMITM},
		{"geo", SiteResult{TCP: ok, TLS: ok, HTTP: &Transfer{Status: StatusOK, HTTP: 302, Geo: true}}, StatusGeo},
		{"frozen", SiteResult{TCP: ok, TLS: ok, HTTP: &Transfer{Status: StatusFrozen}}, StatusFrozen},
		{"dns", SiteResult{TCP: ok, TLS: ok, DNS: StatusInjected, HTTP: &Transfer{Status: StatusOK, HTTP: 200}}, StatusDNSOnly},
		{"fine", SiteResult{TCP: ok, TLS: ok, DNS: StatusOK, HTTP: &Transfer{Status: StatusOK, HTTP: 200}}, StatusOK},
	}
	for _, test := range cases {
		if got := siteVerdict(test.result); got != test.want {
			t.Errorf("%s: got %s, want %s", test.name, got, test.want)
		}
	}
}

func TestFactsWhitelistMode(t *testing.T) {
	report := &Report{
		Sites: []SiteResult{
			{ID: "yandex", Verdict: StatusOK},
			{ID: "github", Verdict: StatusSNIWhitelist},
			{ID: "wikipedia", Verdict: StatusSNIWhitelist},
			{ID: "google", Verdict: StatusSNIWhitelist},
			{ID: "chatgpt", Verdict: StatusSNIBlocked},
		},
		Hosting: []HostingResult{
			{ID: "hetzner-fsn", Foreign: true, Verdict: StatusTLSBlocked},
			{ID: "yandex-cloud", Verdict: StatusOK},
		},
		SNI: &SNIReport{Filtered: true, Passed: []string{"ya.ru"}},
	}
	// Allowed names pass to foreign addresses: a white list of names.
	facts := deriveFacts(report)
	if facts.Mode != "sni_whitelist" || !facts.WhitelistBySNI {
		t.Fatalf("facts %+v", facts)
	}
	// A provider letting one connection through does not end it.
	report.Hosting[0].Verdict = StatusOK
	if facts := deriveFacts(report); facts.Mode != "sni_whitelist" {
		t.Fatalf("an open provider ended white list mode: %+v", facts)
	}
	// Nothing answers at the foreign addresses, whatever the name: a white
	// list by address.
	report.SNI = &SNIReport{}
	timeout := &Step{Status: StatusTimeout}
	for index := range report.Sites {
		report.Sites[index].NoSNI, report.Sites[index].WhiteSNI = timeout, timeout
	}
	if facts := deriveFacts(report); facts.Mode != "whitelist" {
		t.Fatalf("closed addresses are not a white list by address: %+v", facts)
	}
	// One of them answering without a name is enough to tell names.
	report.Sites[2].NoSNI = &Step{Status: StatusOK}
	if facts := deriveFacts(report); facts.Mode != "sni_whitelist" {
		t.Fatalf("an answering address left the name list: %+v", facts)
	}
	report.Sites[2].NoSNI = timeout
	report.Sites[1].Verdict = StatusOK
	if facts := deriveFacts(report); facts.Mode != "filtered" {
		t.Fatalf("an open regular site leaves white list mode: %+v", facts)
	}
}

func TestSessionLifecycle(t *testing.T) {
	// No known section: the run only stamps the report and finishes.
	id, err := Start(Request{Sections: []Section{"none"}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		snapshot, err := State(id)
		if err != nil {
			t.Fatal(err)
		}
		if !snapshot.Running {
			if !strings.Contains(string(snapshot.Report), `"version":1`) {
				t.Fatalf("report %s", snapshot.Report)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := State("missing"); err == nil {
		t.Fatal("an unknown id has a state")
	}
	if err := Cancel(id); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogLoads(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Sites) == 0 || len(cat.Hosting) == 0 || len(cat.Resolvers) == 0 || len(cat.DNSControl) == 0 {
		t.Fatal("catalog sections are empty")
	}
	seen := map[string]bool{}
	whitelist, regular := 0, 0
	for _, site := range cat.Sites {
		if seen[site.ID] {
			t.Errorf("duplicate site %s", site.ID)
		}
		seen[site.ID] = true
		if site.Whitelist {
			whitelist++
		}
		if site.Regular {
			regular++
		}
	}
	if whitelist == 0 || regular == 0 {
		t.Error("white list mode needs both control groups")
	}
}

// recordingConn keeps every write for inspection.
type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestWriteRecordsReframesTheHello(t *testing.T) {
	payload := make([]byte, 1700)
	for index := range payload {
		payload[index] = byte(index)
	}
	hello := append([]byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}, payload...)
	recorder := &recordingConn{}
	conn := &countingConn{Conn: recorder, fragment: true}
	if n, err := conn.Write(hello); err != nil || n != len(hello) {
		t.Fatalf("write = %d, %v", n, err)
	}
	var joined []byte
	for _, record := range recorder.writes {
		size := int(record[3])<<8 | int(record[4])
		if record[0] != 0x16 || size != len(record)-5 || size < 1 || size > 200 {
			t.Fatalf("bad record header %v, %d bytes", record[:5], len(record))
		}
		joined = append(joined, record[5:]...)
	}
	if len(recorder.writes) < 8 || !bytes.Equal(joined, payload) {
		t.Fatalf("%d records do not carry the hello", len(recorder.writes))
	}
	// Later writes pass untouched.
	_, _ = conn.Write([]byte("next"))
	if string(recorder.writes[len(recorder.writes)-1]) != "next" {
		t.Fatal("a later write was re-framed")
	}
}

func TestCutHellosStillHandshake(t *testing.T) {
	server := blobServer(t, 0)
	address := netip.MustParseAddrPort(server.Listener.Addr().String())
	p := newProber(context.Background(), Request{}, catalog{})
	for _, options := range []tlsOptions{{sni: "example.com", split: true}, {sni: "example.com", fragment: true}} {
		if step := p.tlsStep(context.Background(), address.Addr(), int(address.Port()), options); step.Status != StatusOK {
			t.Fatalf("%+v: %+v", options, step)
		}
	}
}
