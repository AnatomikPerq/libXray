//go:build windows || (linux && !android)

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadConfigChecksIntegrity(t *testing.T) {
	directory := commandTestDirectory(t)
	path := filepath.Join(directory, "xray.json")
	config := []byte(`{"log":{"loglevel":"none"}}`)
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(config)
	good := hex.EncodeToString(sum[:])

	if _, err := readConfig(runOptions{configPath: path, configSHA256: good}); err != nil {
		t.Fatalf("matching config rejected: %v", err)
	}
	if _, err := readConfig(runOptions{configPath: path}); err != nil {
		t.Fatalf("config without an expected hash rejected: %v", err)
	}
	// A non-elevated process swapping the file after UAC must be caught.
	if err := os.WriteFile(path, []byte(`{"log":{"access":"C:\\evil.log"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(runOptions{configPath: path, configSHA256: good}); err == nil {
		t.Fatal("tampered config accepted")
	}
}

func TestParseRejectsMalformedConfigHash(t *testing.T) {
	for _, hash := range []string{"abc", string(bytes.Repeat([]byte("z"), 64))} {
		if _, err := parseRunOptions([]string{"run", "-config", "x.json", "-config-sha256", hash}); err == nil {
			t.Fatalf("hash %q accepted", hash)
		}
	}
}

func TestGuardLogFilesPinsConfiguredLogs(t *testing.T) {
	directory := commandTestDirectory(t)
	access := filepath.Join(directory, "access.log")
	config := []byte(`{"log":{"access":` + jsonString(access) + `,"error":"none"}}`)
	files, err := guardLogFiles(config)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(files)
	if len(files) != 1 {
		t.Fatalf("guarded %d files, want 1", len(files))
	}
	if _, err := os.Stat(access); err != nil {
		t.Fatalf("access log was not created: %v", err)
	}
}

func TestStopRequestedFiresWhenFileAppears(t *testing.T) {
	path := filepath.Join(commandTestDirectory(t), "core.stop")
	done := stopRequested(path)
	select {
	case <-done:
		t.Fatal("stopped before the file existed")
	case <-time.After(400 * time.Millisecond):
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop file was not noticed")
	}
}

func TestCommandWritesErrorOnlyThroughVerifiedFile(t *testing.T) {
	path := filepath.Join(commandTestDirectory(t), "xray.json.error")
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-config", "xray.json", "-error-file", path}
	var stdout, stderr bytes.Buffer
	code := execute(args, func(runOptions) error {
		return errors.New("boom")
	}, &stdout, &stderr)
	data, _ := os.ReadFile(path)
	if code != 1 || string(data) != "boom" {
		t.Fatalf("code=%d, file=%q", code, data)
	}
}

func jsonString(value string) string {
	var buffer bytes.Buffer
	buffer.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			buffer.WriteByte('\\')
		}
		buffer.WriteRune(r)
	}
	buffer.WriteByte('"')
	return buffer.String()
}
