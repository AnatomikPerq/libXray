package libXray

import (
	"net/netip"
	"testing"
)

// Names need a DNS server; the order is checked on literals the resolver
// returns as they are.
func TestResolveHostRejectsEmptyAndKeepsLiterals(t *testing.T) {
	if _, err := resolveHost(ResolveHostRequest{}); err == nil {
		t.Fatal("empty host accepted")
	}
	for literal, want := range map[string]string{
		"2001:db8::1":      "2001:db8::1",
		"192.0.2.7":        "192.0.2.7",
		"::ffff:192.0.2.7": "192.0.2.7",
	} {
		got, err := resolveHost(ResolveHostRequest{Host: literal})
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("%s: %v %v", literal, got, err)
		}
		if _, err := netip.ParseAddr(got[0]); err != nil {
			t.Fatal(err)
		}
	}
}
