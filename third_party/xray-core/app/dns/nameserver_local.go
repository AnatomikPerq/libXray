package dns

import (
	"context"
	go_errors "errors"
	gonet "net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	"golang.org/x/net/dns/dnsmessage"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client *localdns.Client
}

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(ctx context.Context, domain string, option dns.IPOption) (ips []net.IP, ttl uint32, err error) {
	start := time.Now()
	ips, ttl, err = s.client.LookupIP(domain, option)
	err = localNameError(err)

	if len(ips) > 0 {
		errors.LogInfo(ctx, "Localhost got answer: ", domain, " -> ", ips)
		log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	}

	return
}

// localNameError reports a name the system resolver does not know as NXDOMAIN,
// the way UDP and DoH servers report it. libXray patch: the resolver's "no
// such host" is neither an RCodeError nor ErrEmptyResponse, so the dns
// outbound answered such a query with nothing at all (the client waited out
// its timeout), and next to another server's NXDOMAIN mergeQueryErrors saw
// two different errors and returned a multierr, with the same result.
func localNameError(err error) error {
	var dnsErr *gonet.DNSError
	if go_errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return dns.RCodeError(dnsmessage.RCodeNameError)
	}
	return err
}

// Name implements Server.
func (s *LocalNameServer) Name() string {
	return "localhost"
}

// IsDisableCache implements Server.
func (s *LocalNameServer) IsDisableCache() bool {
	return true
}

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	errors.LogInfo(context.Background(), "DNS: created localhost client")
	return &LocalNameServer{
		client: localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient(ipOption dns.IPOption) *Client {
	return &Client{id: "localhost", server: NewLocalNameServer(), ipOption: &ipOption}
}
