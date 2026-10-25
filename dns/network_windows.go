//go:build windows

package dns

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// interfaceResolvers lists the IPv4 DNS servers Windows has for iface, in
// its order.
func interfaceResolvers(iface *net.Interface) []net.IP {
	size := uint32(16 * 1024)
	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0,
			first,
			&size,
		)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if int(adapter.IfIndex) != iface.Index {
				continue
			}
			var servers []net.IP
			for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
				if ip := server.Address.IP().To4(); ip != nil && !ip.IsLoopback() {
					servers = append(servers, ip)
				}
			}
			return servers
		}
		return nil
	}
	return nil
}
