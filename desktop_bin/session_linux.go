//go:build linux && !android

package main

// watchSessionEnd has nothing to watch: the Linux Core never engages a kill
// switch.
func watchSessionEnd(func()) error { return nil }
