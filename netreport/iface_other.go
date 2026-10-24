//go:build !windows

package netreport

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
)

// interfaceInfo reads what the standard library offers. Mobile platforms
// tell the connection type themselves (the App knows Wi-Fi from cellular);
// the system resolver comes from resolv.conf where there is one.
func interfaceInfo(name string) (*InterfaceInfo, error) {
	var iface *net.Interface
	if name != "" {
		found, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		iface = found
	} else {
		conn, err := net.Dial("udp4", "1.1.1.1:53")
		if err != nil {
			return nil, err
		}
		local := conn.LocalAddr().(*net.UDPAddr).IP
		conn.Close()
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for index := range interfaces {
			addrs, _ := interfaces[index].Addrs()
			for _, addr := range addrs {
				if prefix, ok := addr.(*net.IPNet); ok && prefix.IP.Equal(local) {
					iface = &interfaces[index]
				}
			}
		}
		if iface == nil {
			return nil, errors.New("no default interface")
		}
	}
	info := &InterfaceInfo{Name: iface.Name, Kind: KindOther, MTU: iface.MTU}
	if strings.HasPrefix(iface.Name, "wl") {
		info.Kind = KindWiFi
	} else if strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "eth") {
		info.Kind = KindEthernet
	} else if strings.HasPrefix(iface.Name, "rmnet") || strings.HasPrefix(iface.Name, "wwan") {
		info.Kind = KindCellular
	}
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		info.Addresses = append(info.Addresses, addr.String())
	}
	if file, err := os.Open("/etc/resolv.conf"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				info.DNS = append(info.DNS, fields[1])
			}
		}
		file.Close()
	}
	return info, nil
}
