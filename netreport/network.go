package netreport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Network struct {
	Interface *InterfaceInfo `json:"interface,omitempty"`
	IPv4      *External      `json:"ipv4,omitempty"`
	IPv6      *External      `json:"ipv6,omitempty"`
	// NAT is set when the interface has no address the internet sees.
	NAT bool `json:"nat"`
}

// Interface kinds.
const (
	KindEthernet     = "ethernet"
	KindWiFi         = "wifi"
	KindUSBTethering = "usb_tethering"
	KindCellular     = "cellular"
	KindPPP          = "ppp"
	KindVirtual      = "virtual"
	KindOther        = "other"
)

type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Kind        string   `json:"kind"`
	MTU         int      `json:"mtu,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	Gateways    []string `json:"gateways,omitempty"`
	DNS         []string `json:"dns,omitempty"`
}

type External struct {
	IP      string `json:"ip"`
	Prefix  string `json:"prefix,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	Holder  string `json:"holder,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	// Lookup is set when the holder could not be looked up (RIPEstat is
	// often unreachable in white list mode).
	Lookup string `json:"lookup,omitempty"`
}

// prepareNetwork reads the interface before any probe: DNS needs its servers.
func (p *prober) prepareNetwork(name string, systemDNS []string) *InterfaceInfo {
	info, err := interfaceInfo(name)
	if err != nil || info == nil {
		info = nil
		if len(systemDNS) == 0 {
			return nil
		}
		info = &InterfaceInfo{Name: name, Kind: KindOther}
	}
	if len(systemDNS) > 0 {
		info.DNS = systemDNS
	}
	var servers []netip.Addr
	for _, text := range info.DNS {
		if ip, err := netip.ParseAddr(text); err == nil && !ip.IsLinkLocalUnicast() {
			servers = append(servers, ip.Unmap())
		}
	}
	p.mu.Lock()
	p.systemDNS = servers
	p.mu.Unlock()
	return info
}

func (p *prober) runNetwork(ctx context.Context, info *InterfaceInfo, report func(*Network)) {
	result := &Network{Interface: info}
	var wait sync.WaitGroup
	wait.Go(func() { result.IPv4 = p.external(ctx, p.cat.ExternalIPv4, false) })
	wait.Go(func() { result.IPv6 = p.external(ctx, p.cat.ExternalIPv6, true) })
	wait.Wait()
	if result.IPv4 != nil && info != nil {
		result.NAT = true
		for _, address := range info.Addresses {
			if prefix, err := netip.ParsePrefix(address); err == nil && prefix.Addr().String() == result.IPv4.IP {
				result.NAT = false
			}
		}
	}
	report(result)
}

func (p *prober) external(ctx context.Context, urls []string, ipv6 bool) *External {
	client := p.familyClient(ipv6)
	for _, url := range urls {
		text, err := getText(ctx, client, url, 256)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil || ip.Is4() == ipv6 {
			continue
		}
		result := &External{IP: ip.String()}
		holder, err := p.ripeHolder(ctx, result.IP)
		if err != nil {
			result.Lookup = detail(err)
			return result
		}
		result.Prefix, result.ASN, result.Holder, result.Country = holder.Prefix, holder.ASN, holder.Holder, holder.Country
		if country, city := p.ripeGeo(ctx, result.IP); country != "" {
			result.Country, result.City = country, city
		}
		return result
	}
	return nil
}

func (p *prober) familyClient(ipv6 bool) *http.Client {
	network := "tcp4"
	if ipv6 {
		network = "tcp6"
	}
	transport := p.http.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return p.dialContext(ctx, network, address)
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func getText(ctx context.Context, client *http.Client, url string, limit int64) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	return string(body), err
}

type holderInfo struct {
	Prefix  string
	ASN     int
	Holder  string
	Country string
}

var (
	holderMu    sync.Mutex
	holderCache = map[string]holderInfo{}
)

// ripeHolder looks up the AS announcing an address: Team Cymru's DNS zone
// first, as plain DNS still works in white list mode where RIPEstat does not,
// then RIPEstat.
func (p *prober) ripeHolder(ctx context.Context, ip string) (holderInfo, error) {
	holderMu.Lock()
	cached, ok := holderCache[ip]
	holderMu.Unlock()
	if ok {
		return cached, nil
	}
	info, err := p.cymruHolder(ctx, ip)
	if err != nil {
		info, err = p.ripeStatHolder(ctx, ip)
	}
	if err != nil {
		return holderInfo{}, err
	}
	holderMu.Lock()
	holderCache[ip] = info
	holderMu.Unlock()
	return info, nil
}

func (p *prober) cymruHolder(ctx context.Context, text string) (holderInfo, error) {
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return holderInfo{}, err
	}
	origin, err := p.plainTXT(ctx, cymruOriginName(ip))
	if err != nil {
		return holderInfo{}, err
	}
	info, err := parseCymruOrigin(origin)
	if err != nil {
		return holderInfo{}, err
	}
	if described, err := p.plainTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", info.ASN)); err == nil {
		info.Holder = parseCymruHolder(described)
	}
	return info, nil
}

func cymruOriginName(ip netip.Addr) string {
	if ip.Is4() {
		octets := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", octets[3], octets[2], octets[1], octets[0])
	}
	bytes := ip.As16()
	nibbles := make([]string, 0, 32)
	for index := 15; index >= 0; index-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", bytes[index]&0x0f), fmt.Sprintf("%x", bytes[index]>>4))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
}

// parseCymruOrigin reads "25159 | 31.173.80.0/21 | RU | ripencc | 2011-04-04".
// Several origin ASNs come space-separated; the first will do.
func parseCymruOrigin(text string) (holderInfo, error) {
	fields := strings.Split(text, "|")
	if len(fields) < 2 {
		return holderInfo{}, errors.New("unexpected origin answer")
	}
	origins := strings.Fields(fields[0])
	if len(origins) == 0 {
		return holderInfo{}, errors.New("no origin AS")
	}
	info := holderInfo{Prefix: strings.TrimSpace(fields[1])}
	if len(fields) >= 3 {
		info.Country = strings.TrimSpace(fields[2])
	}
	if _, err := fmt.Sscan(origins[0], &info.ASN); err != nil {
		return holderInfo{}, err
	}
	return info, nil
}

// parseCymruHolder reads "25159 | RU | ripencc | 2002-08-13 | SONICDUO-AS - PJSC MegaFon, RU".
// Cymru writes the quotes of a name as underscores; paired ones go back.
func parseCymruHolder(text string) string {
	parts := strings.Split(text, "|")
	if len(parts) < 5 {
		return ""
	}
	holder := strings.TrimSpace(parts[4])
	if count := strings.Count(holder, "_"); count > 0 && count%2 == 0 {
		holder = strings.ReplaceAll(holder, "_", "\"")
	}
	return holder
}

// plainTXT asks resolvers that answer this zone honestly in practice.
func (p *prober) plainTXT(ctx context.Context, name string) (string, error) {
	for _, server := range []string{"77.88.8.8", "9.9.9.9", "8.8.8.8"} {
		answers, err := p.queryUDP(ctx, netip.MustParseAddr(server), name, dns.TypeTXT, 0)
		if err == nil && len(answers) > 0 && len(answers[0].Text) > 0 {
			return strings.Join(answers[0].Text, ""), nil
		}
	}
	return "", errors.New("no answer for " + name)
}

func (p *prober) ripeStatHolder(ctx context.Context, ip string) (holderInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	text, err := getText(ctx, p.http, "https://stat.ripe.net/data/prefix-overview/data.json?resource="+ip, 256*1024)
	if err != nil {
		return holderInfo{}, err
	}
	var overview struct {
		Data struct {
			Resource string `json:"resource"`
			ASNs     []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &overview); err != nil {
		return holderInfo{}, err
	}
	if len(overview.Data.ASNs) == 0 {
		return holderInfo{}, errors.New("no AS announces the address")
	}
	return holderInfo{Prefix: overview.Data.Resource, ASN: overview.Data.ASNs[0].ASN, Holder: overview.Data.ASNs[0].Holder}, nil
}

func (p *prober) ripeGeo(ctx context.Context, ip string) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	text, err := getText(ctx, p.http, "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource="+ip, 256*1024)
	if err != nil {
		return "", ""
	}
	var geo struct {
		Data struct {
			Located []struct {
				Locations []struct {
					Country string `json:"country"`
					City    string `json:"city"`
				} `json:"locations"`
			} `json:"located_resources"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(text), &geo) != nil || len(geo.Data.Located) == 0 || len(geo.Data.Located[0].Locations) == 0 {
		return "", ""
	}
	location := geo.Data.Located[0].Locations[0]
	return location.Country, location.City
}
