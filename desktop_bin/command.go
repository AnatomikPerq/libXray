//go:build windows || (linux && !android)

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

type runOptions struct {
	dns           string
	interfaceName string
	configPath    string
	errorFile     string
	stopFile      string
	configSHA256  string
}

func parseRunOptions(args []string) (runOptions, error) {
	var options runOptions
	if len(args) == 0 || args[0] != "run" {
		return options, errors.New("expected run command")
	}

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.dns, "dns", "", "DNS server IP endpoint")
	flags.StringVar(&options.interfaceName, "interface", "", "outbound network interface")
	flags.StringVar(&options.configPath, "config", "", "Xray JSON configuration path")
	flags.StringVar(&options.errorFile, "error-file", "", "also write command errors to this file")
	flags.StringVar(&options.stopFile, "stop-file", "", "stop gracefully once this file appears")
	flags.StringVar(&options.configSHA256, "config-sha256", "", "refuse a config with another SHA-256")
	if err := flags.Parse(args[1:]); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, errors.New("unexpected positional arguments")
	}
	if options.configPath == "" {
		return options, errors.New("config is required")
	}
	// TUN mode must pin the Core's own DNS to the physical interface, or its
	// queries loop back into the tunnel. System proxy mode has no tunnel and
	// follows normal OS routing, so it passes neither option.
	if (options.dns == "") != (options.interfaceName == "") {
		return options, errors.New("dns and interface must be given together")
	}
	if options.configSHA256 != "" && !isSHA256Hex(options.configSHA256) {
		return options, errors.New("config-sha256 must be 64 hex characters")
	}
	return options, nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

func execute(args []string, run func(runOptions) error, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stdout, "Usage: xray run [-dns <IP:port> -interface <name>] -config <xray.json> [-config-sha256 <hex>] [-error-file <path>] [-stop-file <path>]")
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		usage()
		return 0
	}

	options, err := parseRunOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		usage()
		return 0
	}
	var diagnostics *os.File
	if err == nil && options.errorFile != "" {
		// Clear the previous failure before starting. Reuse a caller-created file
		// so an elevated process preserves the caller's read permissions, and
		// write only through this verified handle.
		diagnostics, err = openOwnedFile(options.errorFile, os.O_TRUNC)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer diagnostics.Close()
	}
	if err == nil {
		err = run(options)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		if diagnostics != nil {
			if _, writeErr := diagnostics.WriteString(err.Error()); writeErr != nil {
				fmt.Fprintln(stderr, writeErr)
			}
		}
		return 1
	}
	return 0
}
