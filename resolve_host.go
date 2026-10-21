package libXray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"
)

// invokeResolveHost resolves a name with Go's own resolver, which queries the
// system's DNS servers from this process. The system resolver would hand the
// query to Windows' DNS Client service instead, and the desktop kill switch
// blocks that service outside the tunnel: the App could not resolve a server
// while it reconnects. The App's own process passes the kill switch.
func invokeResolveHost(payload []byte) string {
	request, err := decodePayload[ResolveHostRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	addresses, err := resolveHost(request)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&ResolveHostResponse{Addresses: addresses}, nil)
}

func resolveHost(request ResolveHostRequest) ([]string, error) {
	if request.Host == "" {
		return nil, errors.New("host is required")
	}
	if address, err := netip.ParseAddr(request.Host); err == nil {
		return []string{address.Unmap().String()}, nil
	}
	timeout := time.Duration(request.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	found, err := resolver.LookupNetIP(ctx, "ip", request.Host)
	if err != nil {
		return nil, err
	}
	// IPv4 first, as most networks route it.
	slices.SortStableFunc(found, func(a, b netip.Addr) int {
		switch {
		case a.Unmap().Is4() == b.Unmap().Is4():
			return 0
		case a.Unmap().Is4():
			return -1
		default:
			return 1
		}
	})
	var addresses []string
	for _, address := range found {
		text := address.Unmap().String()
		if !slices.Contains(addresses, text) {
			addresses = append(addresses, text)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("no addresses for " + request.Host)
	}
	return addresses, nil
}
