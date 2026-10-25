//go:build windows || (linux && !android)

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// SetDNS installs a process-wide resolver bound to interfaceName.
func SetDNS(server, interfaceName string) error {
	if interfaceName == "" {
		return errors.New("dns interface is required")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	if err := validateDNSInterface(iface); err != nil {
		return err
	}

	resolver, err := newProtectedResolver(server, func(network string, fd uintptr) error {
		return bindDNSInterface(network, fd, iface)
	})
	if err != nil {
		return err
	}
	if err := preflightResolver(resolver, server); err != nil {
		return err
	}

	installDefaultResolver(resolver)
	return nil
}

// NetworkDNS asks SetNetworkDNS for the interface's own resolver.
const NetworkDNS = "network"

// SetNetworkDNS installs the first resolver iface is configured with that
// answers, or fallback when it has none or none answers, and returns it.
func SetNetworkDNS(interfaceName, fallback string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}
	candidates := make([]string, 0, 3)
	for _, ip := range interfaceResolvers(iface) {
		candidates = append(candidates, net.JoinHostPort(ip.String(), "53"))
	}
	candidates = append(candidates, fallback)
	var errs []error
	for i, server := range candidates {
		if err := SetDNS(server, interfaceName); err != nil {
			errs = append(errs, err)
			continue
		}
		// SetDNS only checks that a socket opens; a resolver that never
		// answers would make every lookup wait out its timeout. The fallback
		// stays even when its probe fails: it may be the probe that is slow.
		if i == len(candidates)-1 || answers() {
			return server, nil
		}
		ResetDNS()
		errs = append(errs, fmt.Errorf("DNS server %s does not answer", server))
	}
	return "", errors.Join(errs...)
}

// answers reports whether the installed resolver answers at all; a name it
// refuses (NXDOMAIN, as filtering resolvers do) still counts.
func answers() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, "www.gstatic.com")
	var dnsErr *net.DNSError
	return err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound)
}

func validateDNSInterface(iface *net.Interface) error {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return errors.New("dns interface must be an active non-loopback interface")
	}
	return nil
}

// ResetDNS restores the resolver that was active before SetDNS.
func ResetDNS() {
	restoreDefaultResolver()
}
