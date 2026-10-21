// Package killswitch keeps traffic from leaving outside the VPN when the
// desktop Core dies.
//
// The App's TUN Core installs the filters at start and removes them only when
// the App disconnects on purpose. They are not tied to the Core's process, so
// a Core that crashes leaves them in place: other programs then reach nothing
// but the local network (if allowed) instead of the internet from the real
// address. Only Windows is implemented, through the Windows Filtering
// Platform; elsewhere every call returns ErrUnsupported.
package killswitch

import (
	"errors"
	"net/netip"
)

// ErrUnsupported is returned where the platform has no kill switch.
var ErrUnsupported = errors.New("kill switch is not supported on this platform")

// Options describe what may still pass while the kill switch is engaged.
// Everything else, in both directions and both IP versions, is blocked.
type Options struct {
	// Apps are executables whose traffic always passes: the Core itself, whose
	// outbounds use the physical interface on purpose, and the App, which
	// hosts the minewire engines and pings nodes so that a working one can be
	// chosen while everything else is blocked.
	Apps []string

	// TunLUID is the TUN adapter whose traffic passes. Zero while the TUN is
	// not up yet, or once the Core that owned it is gone.
	TunLUID uint64

	// AllowLAN lets traffic to private, link-local and multicast addresses
	// pass, except DNS: a resolver on the local network would forward the
	// names to the provider.
	AllowLAN bool

	// Allow adds networks that pass like the local network.
	Allow []netip.Prefix

	// Persistent keeps the filters across a reboot. Otherwise they live until
	// they are removed or Windows restarts its filtering engine.
	Persistent bool

	// blockScope narrows every block filter to these networks. Tests set it to
	// documentation ranges, so that real filters can be installed without
	// cutting off the machine that runs them.
	blockScope []netip.Prefix
}

// lanPrefixes are the networks AllowLAN lets through.
var lanPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

// passingPrefixes returns the networks that pass like the local network.
func (o Options) passingPrefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	if o.AllowLAN {
		prefixes = append(prefixes, lanPrefixes...)
	}
	for _, prefix := range o.Allow {
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes
}
