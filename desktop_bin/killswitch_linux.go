//go:build linux && !android

package main

import "github.com/xtls/libxray/killswitch"

// interfaceLUID is never reached: the Linux kill switch does not engage.
func interfaceLUID(string) (uint64, error) { return 0, killswitch.ErrUnsupported }
