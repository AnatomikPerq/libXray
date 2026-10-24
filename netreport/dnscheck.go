package netreport

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSReport struct {
	// System lists the interface's own DNS servers.
	System    []string         `json:"system,omitempty"`
	Resolvers []ResolverResult `json:"resolvers"`
	// Port53Intercepted is set when a host that runs no DNS server answered
	// a query: the network answers every UDP 53 packet itself.
	Port53Intercepted bool `json:"port53Intercepted"`
}

type ResolverResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	System  bool   `json:"system,omitempty"`
	Status  Status `json:"status"`
	RttMs   int64  `json:"rttMs,omitempty"`
	// LossPct is the share of queries from fresh sockets left unanswered.
	LossPct int `json:"lossPct"`
	// Egress is the address the resolver queries authoritative servers
	// from, with its holder; Intercepted is set when the holder is not the
	// resolver's operator.
	Egress      *Egress      `json:"egress,omitempty"`
	Intercepted bool         `json:"intercepted,omitempty"`
	DoH         *Step        `json:"doh,omitempty"`
	Names       []NameResult `json:"names"`
}

type Egress struct {
	IP     string `json:"ip"`
	ASN    int    `json:"asn,omitempty"`
	Holder string `json:"holder,omitempty"`
}

type NameResult struct {
	Name      string      `json:"name"`
	Status    Status      `json:"status"`
	Answers   []dnsAnswer `json:"answers,omitempty"`
	Reference []string    `json:"reference,omitempty"`
}

const (
	lossQueries   = 10
	deadAfter     = 3
	injectionWait = 1200 * time.Millisecond
)

func (p *prober) runDNS(ctx context.Context, report func(*DNSReport)) {
	result := &DNSReport{Resolvers: []ResolverResult{}}
	var targets []resolverEntry
	p.mu.Lock()
	system := slices.Clone(p.systemDNS)
	p.mu.Unlock()
	for _, server := range system {
		result.System = append(result.System, server.String())
		if server.Is4() {
			targets = append(targets, resolverEntry{ID: "system", Name: "System", Address: server.String()})
		}
	}
	targets = append(targets, p.cat.Resolvers...)
	result.Resolvers = make([]ResolverResult, len(targets))

	names := append(slices.Clone(p.cat.DNSControl), p.cat.DNSProbe...)
	reference := p.referenceAnswers(ctx, names)

	var wait sync.WaitGroup
	for index, target := range targets {
		wait.Go(func() {
			result.Resolvers[index] = p.checkResolver(ctx, target, names, reference)
		})
	}
	wait.Go(func() {
		result.Port53Intercepted = p.port53Intercepted(ctx)
	})
	wait.Wait()
	for index := range result.Resolvers {
		result.Resolvers[index].System = targets[index].ID == "system"
	}
	report(result)
}

// referenceAnswers resolves every name over DoH; names DoH could not answer
// stay out of the comparison.
func (p *prober) referenceAnswers(ctx context.Context, names []string) map[string][]netip.Addr {
	reference := map[string][]netip.Addr{}
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, name := range names {
		wait.Go(func() {
			addrs, source, err := p.lookup(ctx, name)
			if err != nil || !strings.HasPrefix(source, "doh:") {
				return
			}
			mu.Lock()
			reference[name] = addrs
			mu.Unlock()
		})
	}
	wait.Wait()
	return reference
}

func (p *prober) checkResolver(ctx context.Context, target resolverEntry, names []string, reference map[string][]netip.Addr) ResolverResult {
	result := ResolverResult{ID: target.ID, Name: target.Name, Address: target.Address, Names: []NameResult{}}
	server, err := netip.ParseAddr(target.Address)
	if err != nil {
		result.Status = StatusError
		return result
	}
	// Loss and round trip from fresh sockets, on the first control name.
	var rtts []int64
	lost := 0
	for range lossQueries {
		answers, err := p.queryUDP(ctx, server, p.cat.DNSControl[0], dns.TypeA, 0)
		if err != nil || len(answers) == 0 {
			lost++
		} else {
			rtts = append(rtts, answers[0].Ms)
		}
		// A resolver that answered none of the first few is down or
		// unreachable from here: each further query would wait out the
		// timeout.
		if ctx.Err() != nil || lost == deadAfter && len(rtts) == 0 {
			break
		}
	}
	if len(rtts) == 0 {
		result.Status = StatusTimeout
		return result
	}
	result.LossPct = lost * 100 / lossQueries
	result.Status = StatusOK
	slices.Sort(rtts)
	result.RttMs = rtts[len(rtts)/2]

	// Names in parallel, each from its own socket: every query waits for a
	// second, injected-then-real, answer.
	result.Names = make([]NameResult, len(names))
	limit := make(chan struct{}, 4)
	var wait sync.WaitGroup
	for index, name := range names {
		wait.Go(func() {
			limit <- struct{}{}
			defer func() { <-limit }()
			answers, err := p.queryUDP(ctx, server, name, dns.TypeA, injectionWait)
			if err != nil || len(answers) == 0 {
				// One retry: a single loss is the resolver's, not a block.
				answers, _ = p.queryUDP(ctx, server, name, dns.TypeA, injectionWait)
			}
			entry := NameResult{Name: name, Answers: answers, Status: p.judgeName(ctx, name, answers, reference[name])}
			for _, ip := range reference[name] {
				entry.Reference = append(entry.Reference, ip.String())
			}
			result.Names[index] = entry
		})
	}
	wait.Wait()
	stubs := map[string]int{}
	for _, entry := range result.Names {
		if len(entry.Answers) > 0 {
			for _, ip := range entry.Answers[0].IPs {
				stubs[ip.String()]++
			}
		}
	}
	// One address answered for unrelated names is a block page.
	for index := range result.Names {
		entry := &result.Names[index]
		if entry.Status != StatusOK || len(entry.Answers) == 0 || slices.Contains(p.cat.DNSControl, entry.Name) {
			continue
		}
		for _, ip := range entry.Answers[0].IPs {
			if stubs[ip.String()] > 1 && !containsAddr(reference[entry.Name], ip) {
				entry.Status = StatusSpoofed
			}
		}
	}

	if target.ID != "system" {
		result.Egress, result.Intercepted = p.resolverEgress(ctx, server, target.Operator)
	}
	if target.DoH != "" {
		start := time.Now()
		_, err := p.queryDoH(ctx, target.DoH, p.cat.DNSControl[0], dns.TypeA)
		step := Step{Status: classify(err), Ms: since(start)}
		if err != nil {
			step.Detail = detail(err)
		}
		result.DoH = &step
	}
	return result
}

// judgeName compares a plain answer with the DoH reference.
func (p *prober) judgeName(ctx context.Context, name string, answers []dnsAnswer, reference []netip.Addr) Status {
	if len(answers) == 0 {
		return StatusTimeout
	}
	if len(answers) > 1 && answers[0].digest != answers[len(answers)-1].digest {
		return StatusInjected
	}
	first := answers[0]
	if len(reference) == 0 {
		// Without a reference only a forged-looking answer can be judged.
		if first.rcode == dns.RcodeNameError && first.AA {
			return StatusNXDomain
		}
		return StatusOK
	}
	switch {
	case first.rcode == dns.RcodeNameError:
		return StatusNXDomain
	case first.rcode != dns.RcodeSuccess:
		return StatusError
	case len(first.IPs) == 0:
		return StatusEmpty
	}
	for _, ip := range first.IPs {
		if containsAddr(reference, ip) {
			return StatusOK
		}
	}
	for _, ip := range first.IPs {
		if bogon(ip) {
			return StatusSpoofed
		}
	}
	// A CDN hands out other addresses than DoH did; a real one holds a
	// certificate for the name.
	if p.certFor(ctx, first.IPs[0], name) == StatusCertInvalid {
		return StatusSpoofed
	}
	return StatusOK
}

// certFor checks that an address serves a valid certificate for the name.
// Only a handshake that completes with a wrong certificate proves anything:
// a refused one may be a block of that address.
func (p *prober) certFor(ctx context.Context, ip netip.Addr, name string) Status {
	key := ip.String() + " " + name
	p.mu.Lock()
	status, found := p.certs[key]
	p.mu.Unlock()
	if found {
		return status
	}
	status = p.tlsStep(ctx, ip, 443, tlsOptions{sni: name, verify: name}).Status
	p.mu.Lock()
	p.certs[key] = status
	p.mu.Unlock()
	return status
}

func containsAddr(list []netip.Addr, ip netip.Addr) bool {
	return slices.Contains(list, ip)
}

func bogon(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("198.18.0.0/15").Contains(ip)
}

// resolverEgress asks Google's authoritative servers which address queried
// them. A public resolver answers with its own network; an intercepted query
// comes out of the provider's.
func (p *prober) resolverEgress(ctx context.Context, server netip.Addr, operator string) (*Egress, bool) {
	answers, err := p.queryUDP(ctx, server, "o-o.myaddr.l.google.com", dns.TypeTXT, 0)
	if err != nil || len(answers) == 0 {
		return nil, false
	}
	var egress *Egress
	for _, text := range answers[0].Text {
		if ip, err := netip.ParseAddr(text); err == nil {
			egress = &Egress{IP: ip.String()}
			break
		}
	}
	if egress == nil {
		return nil, false
	}
	holder, err := p.ripeHolder(ctx, egress.IP)
	if err != nil {
		return egress, false
	}
	egress.ASN, egress.Holder = holder.ASN, holder.Holder
	if operator == "" || egress.Holder == "" {
		return egress, false
	}
	lower := strings.ToLower(egress.Holder)
	for _, name := range strings.Split(operator, "|") {
		if strings.Contains(lower, name) {
			return egress, false
		}
	}
	return egress, true
}

// port53Intercepted queries web servers that run no DNS server.
func (p *prober) port53Intercepted(ctx context.Context) bool {
	for _, host := range []string{"ya.ru", "speedtest.selectel.ru"} {
		addrs, _, err := p.lookup(ctx, host)
		if err != nil || len(addrs) == 0 {
			continue
		}
		answers, _ := p.queryUDP(ctx, addrs[0], p.cat.DNSControl[0], dns.TypeA, 0)
		if len(answers) > 0 {
			return true
		}
	}
	return false
}
