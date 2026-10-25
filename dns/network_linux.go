//go:build linux && !android

package dns

import (
	"net"
	"os"
	"strings"
)

// interfaceResolvers lists the IPv4 name servers of resolv.conf. A local
// stub (systemd-resolved's 127.0.0.53) is skipped: a socket bound to the
// physical interface cannot reach it.
func interfaceResolvers(_ *net.Interface) []net.IP {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []net.IP
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]).To4(); ip != nil && !ip.IsLoopback() {
			servers = append(servers, ip)
		}
	}
	return servers
}
