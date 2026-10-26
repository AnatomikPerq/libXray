package dns

import (
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// libXray patch: a name the system resolver does not know is NXDOMAIN, as
// a UDP server says it, so the dns outbound answers instead of staying silent.
func TestLocalNameServerReportsUnknownNameAsNXDOMAIN(t *testing.T) {
	server, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go answerNXDOMAIN(server)

	previous := gonet.DefaultResolver
	gonet.DefaultResolver = &gonet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (gonet.Conn, error) {
			var dialer gonet.Dialer
			return dialer.DialContext(ctx, "udp", server.LocalAddr().String())
		},
	}
	defer func() { gonet.DefaultResolver = previous }()

	_, _, err = NewLocalNameServer().QueryIP(context.Background(),
		"nosuchname.example.local", dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if got := dns.RCodeFromError(err); got != uint16(dnsmessage.RCodeNameError) {
		t.Fatalf("rcode %d from %v, want NXDOMAIN", got, err)
	}
}

// Next to another server's NXDOMAIN the merged error is still NXDOMAIN, not a
// multierr the dns outbound cannot answer with.
func TestLocalAndUDPNameErrorsMergeIntoNXDOMAIN(t *testing.T) {
	local := localNameError(&gonet.DNSError{Err: "no such host", Name: "x.local", IsNotFound: true})
	udp := dns.RCodeError(dnsmessage.RCodeNameError)
	merged := mergeQueryErrors("x.local", []error{local, udp})
	if got := dns.RCodeFromError(merged); got != uint16(dnsmessage.RCodeNameError) {
		t.Fatalf("rcode %d from %v, want NXDOMAIN", got, merged)
	}
}

// Other failures (a timeout, a refused socket) stay what they were.
func TestLocalNameErrorKeepsOtherFailures(t *testing.T) {
	timeout := &gonet.DNSError{Err: "i/o timeout", Name: "x.local", IsTimeout: true}
	if got := localNameError(timeout); got != error(timeout) {
		t.Fatalf("got %v, want the timeout itself", got)
	}
	if localNameError(nil) != nil {
		t.Fatal("nil became an error")
	}
}

func answerNXDOMAIN(conn gonet.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(buf[:n])
		if err != nil {
			continue
		}
		question, err := parser.Question()
		if err != nil {
			continue
		}
		reply := dnsmessage.Message{
			Header: dnsmessage.Header{ID: header.ID, Response: true,
				RecursionAvailable: true, RCode: dnsmessage.RCodeNameError},
			Questions: []dnsmessage.Question{question},
		}
		packed, err := reply.Pack()
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.WriteTo(packed, addr)
	}
}
