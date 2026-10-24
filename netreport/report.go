// Package netreport measures how the user's network treats DNS, TLS, UDP and
// the networks VPN servers live in, so the user can hand a protocol author or
// a VPN provider a factual report instead of "it doesn't work".
//
// Every probe runs from this process and binds to the interface the request
// names, so a running tunnel, the system proxy and the system resolver never
// take part. Target addresses come from DoH (or another resolver that is not
// the network's own), so a spoofed DNS answer is reported but does not hide
// what happens on the way to the real address.
package netreport

import (
	_ "embed"
	"encoding/json"
	"sync"
	"time"
)

// Version is the report format; viewers refuse a newer major.
const Version = 1

type Section string

const (
	SectionNetwork Section = "network"
	SectionDNS     Section = "dns"
	SectionSites   Section = "sites"
	SectionHosting Section = "hosting"
	SectionUDP     Section = "udp"
)

var allSections = []Section{SectionNetwork, SectionDNS, SectionSites, SectionHosting, SectionUDP}

type Request struct {
	// Interface binds every probe to this interface; empty uses the one the
	// default route takes.
	Interface string `json:"interface,omitempty"`
	// SystemDNS replaces the interface's resolvers. Android and iOS hide
	// them from Go; the App reads them from the platform.
	SystemDNS []string  `json:"systemDns,omitempty"`
	Sections  []Section `json:"sections,omitempty"`
	// Sites are extra hosts checked like the catalog's services.
	Sites []string `json:"sites,omitempty"`
	// MaxBytes caps each download; 0 means defaultMaxBytes.
	MaxBytes int64 `json:"maxBytes,omitempty"`
	// Bypass retries a refused TLS handshake with the ClientHello split
	// inside the SNI, the trick DPI bypass tools start with.
	Bypass bool `json:"bypass,omitempty"`
}

const (
	defaultMaxBytes = 256 * 1024
	minMaxBytes     = 64 * 1024
	maxMaxBytes     = 4 * 1024 * 1024
)

// Status is one probe's outcome. Transport outcomes describe what the client
// saw; verdicts (SiteResult.Verdict, HostingResult.Verdict) interpret them.
type Status string

const (
	StatusOK          Status = "ok"
	StatusTimeout     Status = "timeout"
	StatusReset       Status = "reset"
	StatusRefused     Status = "refused"
	StatusUnreachable Status = "unreachable"
	// StatusClosed is a FIN in the middle of a handshake or before any
	// response.
	StatusClosed Status = "closed"
	// StatusAlert is a TLS alert from the other side: the ClientHello got
	// through, the server just did not like it.
	StatusAlert       Status = "alert"
	StatusCertInvalid Status = "cert_invalid"
	// StatusFrozen is a transfer that stopped for good after a few dozen
	// packets, the TSPU "16-20 KB" (l4-25) limit.
	StatusFrozen  Status = "frozen"
	StatusStalled Status = "stalled"
	StatusSlow    Status = "slow"
	StatusError   Status = "error"
	StatusSkipped Status = "skipped"

	StatusSpoofed  Status = "spoofed"
	StatusInjected Status = "injected"
	StatusNXDomain Status = "nxdomain"
	StatusEmpty    Status = "empty"

	StatusDNSOnly   Status = "dns_only"
	StatusIPBlocked Status = "ip_blocked"
	// StatusSNIBlocked: the real name fails, a made-up one passes; the
	// classic blacklist by name.
	StatusSNIBlocked Status = "sni_blocked"
	// StatusSNIWhitelist: only names from the white list pass to this
	// address; StatusNoSNIOnly: only a ClientHello without a name passes.
	StatusSNIWhitelist Status = "sni_whitelist"
	StatusNoSNIOnly    Status = "nosni_only"
	StatusTLSBlocked   Status = "tls_blocked"
	StatusMITM         Status = "mitm"
	StatusStub         Status = "stub"
	StatusGeo          Status = "geo"
	StatusHTTPError    Status = "http_error"
)

// Step is one network operation.
type Step struct {
	Status Status `json:"status"`
	Ms     int64  `json:"ms,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Version   int       `json:"version"`
	Started   time.Time `json:"started"`
	Duration  int64     `json:"durationMs"`
	Interface string    `json:"interface,omitempty"`
	// Timings holds each section's duration in milliseconds.
	Timings map[Section]int64 `json:"timings,omitempty"`
	Network *Network          `json:"network,omitempty"`
	DNS     *DNSReport        `json:"dns,omitempty"`
	Sites   []SiteResult      `json:"sites,omitempty"`
	Hosting []HostingResult   `json:"hosting,omitempty"`
	SNI     *SNIReport        `json:"sni,omitempty"`
	UDP     *UDPReport        `json:"udp,omitempty"`
	Facts   *Facts            `json:"facts,omitempty"`
}

//go:embed catalog.json
var catalogJSON []byte

type catalog struct {
	Resolvers    []resolverEntry `json:"resolvers"`
	DNSControl   []string        `json:"dnsControl"`
	DNSProbe     []string        `json:"dnsProbe"`
	Sites        []siteEntry     `json:"sites"`
	Hosting      []hostingEntry  `json:"hosting"`
	WhitelistSNI []string        `json:"whitelistSni"`
	STUN         []stunEntry     `json:"stun"`
	QUIC         []quicEntry     `json:"quic"`
	ExternalIPv4 []string        `json:"externalIPv4"`
	ExternalIPv6 []string        `json:"externalIPv6"`
}

type resolverEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	DoH     string `json:"doh"`
	// Operator holds substrings of the AS holder that answers for this
	// resolver; another holder means the queries were intercepted.
	Operator string `json:"operator"`
}

type siteEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"`
	Host  string `json:"host"`
	Path  string `json:"path"`
	QUIC  bool   `json:"quic"`
	// Whitelist marks Russian services that stay open in "white list" mode;
	// Regular marks foreign sites that are not blocked anywhere in Russia.
	// Together they tell whitelist mode from ordinary blocking.
	Whitelist bool        `json:"whitelist"`
	Regular   bool        `json:"regular"`
	Geo       *geoMarkers `json:"geo"`
}

// geoMarkers recognize a service that refuses the user's country itself.
type geoMarkers struct {
	Status   []int    `json:"status"`
	Body     []string `json:"body"`
	Location []string `json:"location"`
}

type hostingEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country"`
	Host    string `json:"host"`
	// Path may hold "{bytes}" for servers that generate a body of any size.
	Path    string `json:"path"`
	Range   bool   `json:"range"`
	Foreign bool   `json:"foreign"`
}

type stunEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type quicEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
}

var (
	catalogOnce   sync.Once
	catalogParsed catalog
	catalogErr    error
)

func defaultCatalog() (catalog, error) {
	catalogOnce.Do(func() {
		catalogErr = json.Unmarshal(catalogJSON, &catalogParsed)
	})
	return catalogParsed, catalogErr
}
