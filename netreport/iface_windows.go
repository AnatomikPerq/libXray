package netreport

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// interfaceInfo describes the named adapter, or the one the default IPv4
// route takes for an empty name.
func interfaceInfo(name string) (*InterfaceInfo, error) {
	var bestIndex uint32
	if name == "" {
		sockaddr := &windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}
		if err := windows.GetBestInterfaceEx(sockaddr, &bestIndex); err != nil {
			return nil, err
		}
	}
	size := uint32(16 * 1024)
	var buffer []byte
	for range 3 {
		buffer = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
	}
	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		friendly := windows.UTF16PtrToString(adapter.FriendlyName)
		if name != "" && !strings.EqualFold(friendly, name) || name == "" && adapter.IfIndex != bestIndex {
			continue
		}
		description := windows.UTF16PtrToString(adapter.Description)
		info := &InterfaceInfo{
			Name:        friendly,
			Description: description,
			Kind:        adapterKind(adapter.IfType, description),
			MTU:         int(adapter.Mtu),
		}
		for unicast := adapter.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
			if ip, ok := netip.AddrFromSlice(unicast.Address.IP()); ok {
				info.Addresses = append(info.Addresses, netip.PrefixFrom(ip.Unmap(), int(unicast.OnLinkPrefixLength)).String())
			}
		}
		for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			if ip, ok := netip.AddrFromSlice(gateway.Address.IP()); ok {
				info.Gateways = append(info.Gateways, ip.Unmap().String())
			}
		}
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			if ip, ok := netip.AddrFromSlice(server.Address.IP()); ok {
				info.DNS = append(info.DNS, ip.Unmap().String())
			}
		}
		return info, nil
	}
	return nil, fmt.Errorf("no adapter %q", name)
}

func adapterKind(ifType uint32, description string) string {
	lower := strings.ToLower(description)
	switch {
	case strings.Contains(lower, "remote ndis"), strings.Contains(lower, "rndis"),
		strings.Contains(lower, "apple mobile device"), strings.Contains(lower, "android"):
		return KindUSBTethering
	case ifType == windows.IF_TYPE_IEEE80211:
		return KindWiFi
	case ifType == 243 || ifType == 244: // IF_TYPE_WWANPP, IF_TYPE_WWANPP2
		return KindCellular
	case ifType == windows.IF_TYPE_PPP:
		return KindPPP
	case ifType == windows.IF_TYPE_TUNNEL || ifType == 53, // IF_TYPE_PROP_VIRTUAL
		strings.Contains(lower, "wintun"), strings.Contains(lower, "wireguard"), strings.Contains(lower, "tap-"),
		strings.Contains(lower, "hyper-v"), strings.Contains(lower, "virtualbox"), strings.Contains(lower, "vmware"):
		return KindVirtual
	case ifType == windows.IF_TYPE_ETHERNET_CSMACD:
		return KindEthernet
	}
	return KindOther
}
