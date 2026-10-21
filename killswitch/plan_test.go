package killswitch

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlanNeedsTheCore(t *testing.T) {
	_, err := plan(Options{})
	require.Error(t, err)
}

func TestPlanBlocksComeFirst(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}, TunLUID: 7, AllowLAN: true})
	require.NoError(t, err)
	seenPermit := false
	for _, r := range rules {
		if r.permit {
			seenPermit = true
			continue
		}
		require.False(t, seenPermit, "block %q after a permit", r.name)
	}
}

func TestPlanCoversEveryLayer(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe", "app.exe"}, TunLUID: 7})
	require.NoError(t, err)
	for _, l := range []layer{connectV4, acceptV4, connectV6, acceptV6} {
		var blockAll, apps, tun, loopback bool
		for _, r := range rules {
			if r.layer != l {
				continue
			}
			switch {
			case !r.permit && len(r.conditions) == 0:
				blockAll = r.weight == weightBlockAll
			case r.weight == weightApps:
				apps = len(r.conditions) == 2
			case r.weight == weightTun:
				tun = r.conditions[0] == condition{kind: condInterface, number: 7}
			case r.weight == weightLoopback:
				loopback = true
			}
		}
		require.True(t, blockAll, "%s: block everything", l)
		require.True(t, apps, "%s: permit both programs", l)
		require.True(t, tun, "%s: permit the tunnel", l)
		require.True(t, loopback, "%s: permit loopback", l)
	}
}

func TestPlanWithoutTunnelPermitsNoInterface(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}})
	require.NoError(t, err)
	for _, r := range rules {
		require.NotEqual(t, uint8(weightTun), r.weight, r.name)
	}
}

func TestPlanLocalNetworkKeepsDNSBlocked(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}, AllowLAN: true})
	require.NoError(t, err)
	var dns, lan int
	for _, r := range rules {
		switch r.weight {
		case weightBlockDNS:
			require.False(t, r.permit)
			require.True(t, r.layer.connect(), "DNS is blocked on the way out")
			dns++
		case weightLAN:
			require.True(t, r.permit)
			for _, c := range r.conditions {
				require.Equal(t, r.layer.ipv6(), c.prefix.Addr().Is6(), "%s gets only its own IP version", r.layer)
			}
			lan++
		}
	}
	require.Equal(t, 2, dns)
	require.Equal(t, 4, lan)
	require.Greater(t, weightBlockDNS, weightLAN, "DNS to a local resolver stays blocked")
	require.Greater(t, weightTun, weightBlockDNS, "DNS through the tunnel passes")
}

func TestPlanWithoutLocalNetworkHasNoDNSRule(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}})
	require.NoError(t, err)
	for _, r := range rules {
		require.NotEqual(t, uint8(weightBlockDNS), r.weight)
		require.NotEqual(t, uint8(weightLAN), r.weight)
	}
}

func TestPlanAllowsExtraNetworksMasked(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}, Allow: []netip.Prefix{netip.MustParsePrefix("100.64.1.2/10")}})
	require.NoError(t, err)
	var found bool
	for _, r := range rules {
		if r.weight == weightLAN && r.layer == connectV4 {
			require.Equal(t, []condition{{kind: condRemotePrefix, prefix: netip.MustParsePrefix("100.64.0.0/10")}}, r.conditions)
			found = true
		}
	}
	require.True(t, found)
}

func TestPlanKeepsSystemTraffic(t *testing.T) {
	rules, err := plan(Options{Apps: []string{"core.exe"}})
	require.NoError(t, err)
	names := map[layer][]string{}
	for _, r := range rules {
		if r.weight == weightSystem {
			names[r.layer] = append(names[r.layer], r.name)
		}
	}
	require.Equal(t, []string{"permit DHCP"}, names[connectV4])
	require.Equal(t, []string{"permit DHCP"}, names[acceptV4])
	require.Equal(t, []string{"permit DHCPv6", "permit neighbor discovery"}, names[connectV6])
	require.Equal(t, []string{"permit DHCPv6", "permit neighbor discovery"}, names[acceptV6])
}

func TestPlanFitsTheKeyRange(t *testing.T) {
	rules, err := plan(Options{
		Apps:     []string{"core.exe", "app.exe"},
		TunLUID:  7,
		AllowLAN: true,
		Allow:    []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("2001:db8::/32")},
	})
	require.NoError(t, err)
	require.LessOrEqual(t, len(rules), maxRules)
}

func TestPlanScopeNarrowsOnlyBlocks(t *testing.T) {
	scope := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	rules, err := plan(Options{Apps: []string{"core.exe"}, AllowLAN: true, blockScope: scope})
	require.NoError(t, err)
	for _, r := range rules {
		last := r.conditions[len(r.conditions)-1]
		if r.permit {
			require.NotContains(t, scope, last.prefix, r.name)
			continue
		}
		require.Equal(t, condRemotePrefix, last.kind, r.name)
		require.Contains(t, scope, last.prefix, r.name)
	}

	_, err = plan(Options{Apps: []string{"core.exe"}, blockScope: scope[:1]})
	require.Error(t, err, "a scope without IPv6 would leave IPv6 blocks unscoped")
}
