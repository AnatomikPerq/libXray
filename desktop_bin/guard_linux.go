//go:build linux && !android

package main

import (
	"fmt"
	"os"
)

func verifyNotRedirected(file *os.File, expected string) error {
	final, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err != nil {
		return err
	}
	if final != expected {
		return errRedirected
	}
	return nil
}
