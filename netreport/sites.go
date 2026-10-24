package netreport

import (
	"context"
	"crypto/rand"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

type SiteResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Group  string `json:"group"`
	Host   string `json:"host"`
	Custom bool   `json:"custom,omitempty"`
	IP     string `json:"ip,omitempty"`
	// Resolve names where the probed address came from.
	Resolve string `json:"resolve,omitempty"`
	// DNS is what the network's own resolver answered, judged against the
	// reference; DNSAnswer its addresses.
	DNS       Status   `json:"dns"`
	DNSAnswer []string `json:"dnsAnswer,omitempty"`
	TCP       Step     `json:"tcp"`
	TLS       Step     `json:"tls"`
	NoSNI     *Step    `json:"noSni,omitempty"`
	RandomSNI *Step    `json:"randomSni,omitempty"`
	WhiteSNI  *Step    `json:"whiteSni,omitempty"`
	WhiteName string   `json:"whiteName,omitempty"`
	// Split and Fragment retry the real name with the ClientHello cut up
	// (Request.Bypass): what DPI bypass at the application level would do.
	Split            *Step     `json:"split,omitempty"`
	Fragment         *Step     `json:"fragment,omitempty"`
	FragmentTransfer *Transfer `json:"fragmentTransfer,omitempty"`
	HTTP             *Transfer `json:"http,omitempty"`
	QUIC             *Step     `json:"quic,omitempty"`
	Verdict          Status    `json:"verdict"`
}

const siteBytes = 96 * 1024

func (p *prober) checkSite(ctx context.Context, entry siteEntry) SiteResult {
	result := SiteResult{ID: entry.ID, Name: entry.Name, Group: entry.Group, Host: entry.Host, DNS: StatusSkipped}
	addrs, source, err := p.lookup(ctx, entry.Host)
	result.Resolve = source
	result.DNS, result.DNSAnswer = p.systemAnswer(ctx, entry.Host, addrs)
	if err != nil || len(addrs) == 0 {
		result.TCP = Step{Status: StatusSkipped}
		result.TLS = Step{Status: StatusSkipped}
		result.Verdict = StatusError
		if result.DNS == StatusNXDomain || result.DNS == StatusSpoofed {
			result.Verdict = result.DNS
		}
		return result
	}
	ip := addrs[0]
	result.IP = ip.String()

	request := fetchOptions{host: entry.Host, path: entry.Path, want: min(p.maxBytes, siteBytes), geo: entry.Geo}
	conn, tcp, handshake := p.handshake(ctx, ip, 443, tlsOptions{sni: entry.Host, verify: entry.Host})
	result.TCP, result.TLS = tcp, handshake
	switch {
	case conn != nil && handshake.Status == StatusOK:
		transfer := fetch(ctx, conn, conn.counter.rx.Load, request)
		result.HTTP = &transfer
	case !failed(tcp.Status) && failed(handshake.Status) && handshake.Status != StatusCertInvalid:
		// The same address with a name nobody blocks, with an allowed
		// one and with none tells a blocked name from a blocked address.
		result.WhiteName = p.whiteName()
		result.NoSNI, result.RandomSNI, result.WhiteSNI = p.tlsVariants(ctx, ip, 443, result.WhiteName)
		if p.bypass {
			result.Split, result.Fragment, result.FragmentTransfer = p.bypassSteps(ctx, ip, entry.Host, request)
		}
	}
	if conn != nil {
		conn.Close()
	}
	if entry.QUIC {
		step := p.quicStep(ctx, ip, entry.Host)
		result.QUIC = &step
	}
	result.Verdict = siteVerdict(result)
	return result
}

func siteVerdict(result SiteResult) Status {
	switch {
	case failed(result.TCP.Status):
		return StatusIPBlocked
	case result.TLS.Status == StatusCertInvalid:
		return StatusMITM
	case failed(result.TLS.Status):
		return tlsFailure(result.NoSNI, result.RandomSNI, result.WhiteSNI)
	case result.HTTP == nil:
		return StatusError
	case result.HTTP.Geo, result.HTTP.HTTP == 451:
		return StatusGeo
	case result.HTTP.Status == StatusFrozen, result.HTTP.Status == StatusSlow:
		return result.HTTP.Status
	case failed(result.HTTP.Status):
		return result.HTTP.Status
	case result.DNS == StatusSpoofed, result.DNS == StatusNXDomain, result.DNS == StatusInjected, result.DNS == StatusEmpty:
		return StatusDNSOnly
	}
	return StatusOK
}

// systemAnswer asks the interface's first IPv4 resolver, the one apps use.
func (p *prober) systemAnswer(ctx context.Context, host string, reference []netip.Addr) (Status, []string) {
	p.mu.Lock()
	var server netip.Addr
	for _, candidate := range p.systemDNS {
		if candidate.Is4() {
			server = candidate
			break
		}
	}
	p.mu.Unlock()
	if !server.IsValid() {
		return StatusSkipped, nil
	}
	answers, err := p.queryUDP(ctx, server, host, dns.TypeA, injectionWait)
	if err != nil || len(answers) == 0 {
		answers, _ = p.queryUDP(ctx, server, host, dns.TypeA, injectionWait)
	}
	var addresses []string
	if len(answers) > 0 {
		for _, ip := range answers[0].IPs {
			addresses = append(addresses, ip.String())
		}
	}
	return p.judgeName(ctx, host, answers, reference), addresses
}

func randomHost() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buffer := make([]byte, 12)
	_, _ = rand.Read(buffer)
	for index := range buffer {
		buffer[index] = alphabet[int(buffer[index])%len(alphabet)]
	}
	return string(buffer) + ".com"
}

// spacing keeps successive connections to one address apart: several at
// once with one SNI trip the "Siberian" limit, which would then be measured
// instead of the block itself.
func spacing(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(150 * time.Millisecond):
	}
}
