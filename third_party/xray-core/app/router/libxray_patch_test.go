package router

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// libXray patch: a sniffed connection's target is its domain, yet the process
// lookup still gets the address the app dialed.
func TestProcessLookupUsesTheOriginalTarget(t *testing.T) {
	ctx := &routing_session.Context{
		Inbound: &session.Inbound{
			Source: net.TCPDestination(net.ParseAddress("198.18.0.1"), 41000),
		},
		Outbound: &session.Outbound{
			OriginalTarget: net.TCPDestination(net.ParseAddress("198.18.3.7"), 443),
			Target:         net.TCPDestination(net.ParseAddress("example.com"), 443),
		},
	}
	var got [5]any
	_, _, _, err := findProcess(ctx, func(network, srcIP string, srcPort uint16, dstIP string, dstPort uint16) (int, string, string, error) {
		got = [5]any{network, srcIP, srcPort, dstIP, dstPort}
		return 10123, "10123", "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [5]any{"tcp", "198.18.0.1", uint16(41000), "198.18.3.7", uint16(443)}
	if got != want {
		t.Fatalf("lookup got %v, want %v", got, want)
	}

	// A target that still has its address wins over the original.
	ctx.Outbound.Target = net.TCPDestination(net.ParseAddress("203.0.113.9"), 443)
	findProcess(ctx, func(_ string, _ string, _ uint16, dstIP string, _ uint16) (int, string, string, error) {
		if dstIP != "203.0.113.9" {
			t.Fatalf("lookup got %s", dstIP)
		}
		return 0, "", "", nil
	})

	if _, ok := originalTarget(&routing_session.Context{}); ok {
		t.Fatal("a context without an outbound has no original target")
	}
}
