//go:build windows

package main

import (
	"net"
	"time"

	"golang.org/x/sys/windows"
)

// interfaceLUID finds the adapter by name. Xray creates it before RunXray
// returns, but Windows may list it a moment later.
func interfaceLUID(name string) (uint64, error) {
	var iface *net.Interface
	var err error
	for deadline := time.Now().Add(5 * time.Second); ; {
		if iface, err = net.InterfaceByName(name); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return 0, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return 0, err
	}
	return row.InterfaceLuid, nil
}
