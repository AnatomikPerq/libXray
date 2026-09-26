//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction needs no privilege on Windows, so it is exactly what a
// non-elevated process would plant to redirect the elevated Core's writes.
func TestOpenOwnedFileRefusesJunctionedPath(t *testing.T) {
	directory := commandTestDirectory(t)
	target := filepath.Join(directory, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(directory, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v %s", err, out)
	}
	defer os.Remove(junction)

	if _, err := openOwnedFile(filepath.Join(junction, "xray.json.error"), os.O_TRUNC); !errors.Is(err, errRedirected) {
		t.Fatalf("write through a junction: err=%v, want errRedirected", err)
	}
	file, err := openOwnedFile(filepath.Join(target, "xray.json.error"), os.O_TRUNC)
	if err != nil {
		t.Fatalf("direct path rejected: %v", err)
	}
	file.Close()

	config := []byte(`{"log":{"error":` + jsonString(filepath.Join(junction, "error.log")) + `}}`)
	if _, err := guardLogFiles(config); !errors.Is(err, errRedirected) {
		t.Fatalf("log through a junction: err=%v, want errRedirected", err)
	}
}
