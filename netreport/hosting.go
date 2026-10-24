package netreport

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// HostingResult describes one provider VPN servers commonly rent from: can
// a TLS connection reach it, and does a transfer survive past the freeze
// window.
type HostingResult struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Country   string    `json:"country,omitempty"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Foreign   bool      `json:"foreign"`
	TCP       Step      `json:"tcp"`
	TLS       Step      `json:"tls"`
	NoSNI     *Step     `json:"noSni,omitempty"`
	RandomSNI *Step     `json:"randomSni,omitempty"`
	Transfer  *Transfer `json:"transfer,omitempty"`
	// WhiteSNI repeats the handshake (and the transfer, if the first one
	// failed) with a name from the white list: when that passes, a REALITY
	// server borrowing such a name would too.
	WhiteSNI      *Step     `json:"whiteSni,omitempty"`
	WhiteName     string    `json:"whiteName,omitempty"`
	WhiteTransfer *Transfer `json:"whiteTransfer,omitempty"`
	// Split and Fragment as for sites (Request.Bypass); FragmentTransfer is
	// the provider's download after a re-framed hello.
	Split            *Step     `json:"split,omitempty"`
	Fragment         *Step     `json:"fragment,omitempty"`
	FragmentTransfer *Transfer `json:"fragmentTransfer,omitempty"`
	Verdict          Status    `json:"verdict"`
}

func (p *prober) checkHosting(ctx context.Context, entry hostingEntry) HostingResult {
	result := HostingResult{ID: entry.ID, Name: entry.Name, Country: entry.Country, Host: entry.Host, Foreign: entry.Foreign}
	addrs, _, err := p.lookup(ctx, entry.Host)
	if err != nil || len(addrs) == 0 {
		result.TCP, result.TLS = Step{Status: StatusSkipped}, Step{Status: StatusSkipped}
		result.Verdict = StatusError
		return result
	}
	ip := addrs[0]
	result.IP = ip.String()
	options := fetchOptions{
		host:        entry.Host,
		path:        strings.ReplaceAll(entry.Path, "{bytes}", strconv.FormatInt(p.maxBytes, 10)),
		want:        p.maxBytes,
		rangeHeader: entry.Range,
		userAgent:   toolAgent,
	}

	conn, tcp, handshake := p.handshake(ctx, ip, 443, tlsOptions{sni: entry.Host, verify: entry.Host})
	result.TCP, result.TLS = tcp, handshake
	if conn != nil {
		if handshake.Status == StatusOK {
			transfer := fetch(ctx, conn, conn.counter.rx.Load, options)
			result.Transfer = &transfer
		}
		conn.Close()
	} else if !failed(tcp.Status) {
		result.WhiteName = p.whiteName()
		result.NoSNI, result.RandomSNI, result.WhiteSNI = p.tlsVariants(ctx, ip, 443, result.WhiteName)
		if p.bypass {
			result.Split, result.Fragment, result.FragmentTransfer = p.bypassSteps(ctx, ip, entry.Host, options)
		}
	}

	// An allowed name, with the same transfer, when the provider's own
	// name failed: that is what a REALITY server there would see.
	ownFailed := failed(handshake.Status) || result.Transfer != nil && failed(result.Transfer.Status)
	if !failed(tcp.Status) && ownFailed && (result.WhiteSNI == nil || reached(result.WhiteSNI.Status)) {
		spacing(ctx)
		if result.WhiteName == "" {
			result.WhiteName = p.whiteName()
		}
		white, _, step := p.handshake(ctx, ip, 443, tlsOptions{sni: result.WhiteName})
		if result.WhiteSNI == nil {
			result.WhiteSNI = &step
		}
		if white != nil {
			transfer := fetch(ctx, white, white.counter.rx.Load, options)
			result.WhiteTransfer = &transfer
			white.Close()
		}
	}
	result.Verdict = hostingVerdict(result)
	return result
}

func hostingVerdict(result HostingResult) Status {
	switch {
	case failed(result.TCP.Status):
		return StatusIPBlocked
	case result.TLS.Status == StatusCertInvalid:
		return StatusMITM
	case failed(result.TLS.Status):
		return tlsFailure(result.NoSNI, result.RandomSNI, result.WhiteSNI)
	case result.Transfer == nil:
		return StatusError
	}
	return result.Transfer.Status
}

// SNIReport lists which server names pass on a network that filters TLS by
// name. A REALITY node is only as good as the name it borrows.
type SNIReport struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	// Filtered is set when a made-up name fails where no name passes.
	Filtered bool     `json:"filtered"`
	Passed   []string `json:"passed,omitempty"`
	Failed   []string `json:"failed,omitempty"`
}

// sniHost answers a handshake for any name: Google's front ends do.
const sniHost = "www.google.com"

// whiteName is the allowed name retries borrow: the first one the SNI check
// saw pass, else the catalog's first.
func (p *prober) whiteName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.passedSNI != "" {
		return p.passedSNI
	}
	if len(p.cat.WhitelistSNI) > 0 {
		return p.cat.WhitelistSNI[0]
	}
	return ""
}

func (p *prober) runSNI(ctx context.Context, report func(*SNIReport)) {
	addrs, _, err := p.lookup(ctx, sniHost)
	if err != nil || len(addrs) == 0 {
		return
	}
	ip := addrs[0]
	result := &SNIReport{Host: sniHost, IP: ip.String()}
	if !reached(p.tlsStep(ctx, ip, 443, tlsOptions{}).Status) {
		// Nothing gets through to this address at all.
		report(result)
		return
	}
	spacing(ctx)
	if reached(p.tlsStep(ctx, ip, 443, tlsOptions{sni: randomHost()}).Status) {
		report(result)
		return
	}
	result.Filtered = true
	var mu sync.Mutex
	limit := make(chan struct{}, 4)
	var wait sync.WaitGroup
	for _, name := range p.cat.WhitelistSNI {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			passed := reached(p.tlsStep(ctx, ip, 443, tlsOptions{sni: name}).Status)
			mu.Lock()
			defer mu.Unlock()
			if passed {
				result.Passed = append(result.Passed, name)
			} else {
				result.Failed = append(result.Failed, name)
			}
		})
	}
	wait.Wait()
	slices.Sort(result.Passed)
	slices.Sort(result.Failed)
	p.mu.Lock()
	for _, name := range p.cat.WhitelistSNI {
		if slices.Contains(result.Passed, name) {
			p.passedSNI = name
			break
		}
	}
	p.mu.Unlock()
	report(result)
}
