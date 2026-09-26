//go:build windows || (linux && !android)

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The Windows TUN Core runs elevated, but its config, diagnostics and log
// files live in the App's per-user data directory, which every process of that
// user can write. Two things keep that from becoming a way to act as admin:
//
//   - the config is checked against a SHA-256 passed on the command line, which
//     a non-elevated process cannot change once UAC has started the Core;
//   - every file the Core writes is opened here first and refused if any part of
//     its path was redirected (junction, symlink). The handle stays open for the
//     life of the process, which also pins the path: a file or a directory with
//     an open file inside cannot be renamed away and replaced.

func readConfig(options runOptions) ([]byte, error) {
	config, err := os.ReadFile(options.configPath)
	if err != nil {
		return nil, err
	}
	if options.configSHA256 != "" {
		sum := sha256.Sum256(config)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), options.configSHA256) {
			return nil, errors.New("config integrity check failed")
		}
	}
	return config, nil
}

// openOwnedFile opens (creating if needed) a file the Core writes and verifies
// that the path resolves to itself.
func openOwnedFile(path string, flag int) (*os.File, error) {
	expected, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(expected, flag|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := verifyNotRedirected(file, expected); err != nil {
		file.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return file, nil
}

// guardLogFiles pins the log files named in the config before Xray opens them.
func guardLogFiles(config []byte) ([]*os.File, error) {
	var parsed struct {
		Log *struct {
			Access string `json:"access"`
			Error  string `json:"error"`
		} `json:"log"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil || parsed.Log == nil {
		// Xray reports malformed configs itself; nothing to guard here.
		return nil, nil
	}
	var files []*os.File
	for _, path := range []string{parsed.Log.Access, parsed.Log.Error} {
		if path == "" || strings.EqualFold(path, "none") {
			continue
		}
		file, err := openOwnedFile(path, os.O_APPEND)
		if err != nil {
			closeAll(files)
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, file := range files {
		file.Close()
	}
}

var errRedirected = errors.New("path is redirected; refusing to write through it")
