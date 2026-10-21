package killswitch

import (
	"fmt"
	"net/netip"
)

// layer is one of the four ALE layers the filters live in: connections out
// (and the first datagram sent) and connections accepted from outside, for
// each IP version.
type layer int

const (
	connectV4 layer = iota
	acceptV4
	connectV6
	acceptV6
)

func (l layer) ipv6() bool    { return l == connectV6 || l == acceptV6 }
func (l layer) connect() bool { return l == connectV4 || l == connectV6 }

func (l layer) String() string {
	return [...]string{"out IPv4", "in IPv4", "out IPv6", "in IPv6"}[l]
}

type conditionKind int

const (
	// condApp matches the executable Options.Apps[index].
	condApp conditionKind = iota
	// condLoopback matches loopback traffic.
	condLoopback
	// condInterface matches traffic whose local interface has LUID number.
	condInterface
	condProtocol
	condLocalPort
	condRemotePort
	condRemotePrefix
)

type condition struct {
	kind   conditionKind
	number uint64 // app index, LUID, protocol or port
	prefix netip.Prefix
}

// rule is one WFP filter. Within the kill switch's sublayer the heaviest
// matching rule decides, so the permits outweigh the blocks they cut holes in.
// Conditions on the same field match when any of them does; conditions on
// different fields must all match.
type rule struct {
	name       string
	layer      layer
	permit     bool
	weight     uint8
	conditions []condition
}

// Weights of the rules, heaviest first.
const (
	weightApps     = 15
	weightLoopback = 14
	weightTun      = 13
	weightSystem   = 12 // DHCP, neighbor discovery
	weightBlockDNS = 11
	weightLAN      = 10
	weightBlockAll = 0
)

// maxRules bounds the filter keys Lift tries to remove. The plan never gets
// near it: 4 layers with at most 8 rules each.
const maxRules = 64

const (
	protocolUDP    = 17
	protocolICMPv6 = 58
)

// neighborDiscovery are the ICMPv6 types of neighbor and multicast listener
// discovery, which IPv6 needs on the local link. WFP puts the ICMP type where
// the local port is, and the code where the remote port is.
var neighborDiscovery = []uint64{130, 131, 132, 133, 134, 135, 136, 137, 143}

// plan lists the filters for o. Blocks come first: Lift removes the filters
// in this order when it cannot use a transaction, and a permit left without
// its block is harmless while a block left without its permits is not.
func plan(o Options) ([]rule, error) {
	if len(o.Apps) == 0 {
		return nil, fmt.Errorf("kill switch needs the Core's own executable")
	}
	layers := []layer{connectV4, acceptV4, connectV6, acceptV6}
	passing := o.passingPrefixes()
	var rules []rule
	for _, l := range layers {
		if len(o.blockScope) > 0 && len(o.scope(l)) == 0 {
			return nil, fmt.Errorf("kill switch test scope has no %s network", l)
		}
	}
	add := func(r rule) {
		if !r.permit {
			r.conditions = append(r.conditions, o.scope(r.layer)...)
		}
		rules = append(rules, r)
	}

	for _, l := range layers {
		add(rule{name: "block everything else", layer: l, weight: weightBlockAll})
	}
	if len(passing) > 0 {
		for _, l := range layers {
			if l.connect() {
				add(rule{name: "block DNS outside the VPN", layer: l, weight: weightBlockDNS,
					conditions: []condition{{kind: condRemotePort, number: 53}}})
			}
		}
	}

	for _, l := range layers {
		apps := make([]condition, len(o.Apps))
		for i := range o.Apps {
			apps[i] = condition{kind: condApp, number: uint64(i)}
		}
		add(rule{name: "permit the VPN's own programs", layer: l, permit: true, weight: weightApps, conditions: apps})
		add(rule{name: "permit loopback", layer: l, permit: true, weight: weightLoopback,
			conditions: []condition{{kind: condLoopback}}})
		if o.TunLUID != 0 {
			add(rule{name: "permit the VPN tunnel", layer: l, permit: true, weight: weightTun,
				conditions: []condition{{kind: condInterface, number: o.TunLUID}}})
		}
		if l.ipv6() {
			add(rule{name: "permit DHCPv6", layer: l, permit: true, weight: weightSystem, conditions: []condition{
				{kind: condProtocol, number: protocolUDP},
				{kind: condLocalPort, number: 546},
				{kind: condRemotePort, number: 547},
			}})
			discovery := []condition{{kind: condProtocol, number: protocolICMPv6}, {kind: condRemotePort, number: 0}}
			for _, typ := range neighborDiscovery {
				discovery = append(discovery, condition{kind: condLocalPort, number: typ})
			}
			add(rule{name: "permit neighbor discovery", layer: l, permit: true, weight: weightSystem, conditions: discovery})
		} else {
			add(rule{name: "permit DHCP", layer: l, permit: true, weight: weightSystem, conditions: []condition{
				{kind: condProtocol, number: protocolUDP},
				{kind: condLocalPort, number: 68},
				{kind: condRemotePort, number: 67},
			}})
		}
		var networks []condition
		for _, prefix := range passing {
			if prefix.Addr().Is6() == l.ipv6() {
				networks = append(networks, condition{kind: condRemotePrefix, prefix: prefix})
			}
		}
		if len(networks) > 0 {
			add(rule{name: "permit the local network", layer: l, permit: true, weight: weightLAN, conditions: networks})
		}
	}
	if len(rules) > maxRules {
		return nil, fmt.Errorf("kill switch plan has %d filters, more than %d", len(rules), maxRules)
	}
	return rules, nil
}

// scope returns the test-only conditions that narrow a block in l.
func (o Options) scope(l layer) []condition {
	var conditions []condition
	for _, prefix := range o.blockScope {
		if prefix.Addr().Is6() == l.ipv6() {
			conditions = append(conditions, condition{kind: condRemotePrefix, prefix: prefix})
		}
	}
	return conditions
}
