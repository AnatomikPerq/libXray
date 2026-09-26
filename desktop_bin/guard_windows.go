//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func verifyNotRedirected(file *os.File, expected string) error {
	final, err := finalPath(windows.Handle(file.Fd()))
	if err != nil {
		return err
	}
	want := expected
	// 8.3 short components would differ from the normalized final path.
	if long, err := longPath(expected); err == nil {
		want = long
	}
	if !strings.EqualFold(stripVerbatim(final), stripVerbatim(want)) {
		return errRedirected
	}
	return nil
}

func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	for {
		// Flags 0 = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
		n, err := windows.GetFinalPathNameByHandle(
			handle, &buffer[0], uint32(len(buffer)), 0,
		)
		if err != nil {
			return "", err
		}
		if int(n) < len(buffer) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		buffer = make([]uint16, n+1)
	}
}

func longPath(path string) (string, error) {
	source, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(source, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

func stripVerbatim(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	return strings.TrimPrefix(path, `\\?\`)
}
