//go:build windows || (linux && !android)

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xtls/libxray/dns"
	"github.com/xtls/libxray/xray"
)

func run(options runOptions) error {
	config, err := readConfig(options)
	if err != nil {
		return err
	}
	logs, err := guardLogFiles(config)
	if err != nil {
		return err
	}
	defer closeAll(logs)
	if options.interfaceName != "" {
		if err := dns.SetDNS(options.dns, options.interfaceName); err != nil {
			return err
		}
		defer dns.ResetDNS()
	}

	if err := xray.RunXray(string(config)); err != nil {
		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
	case <-stopRequested(options.stopFile):
	}
	return xray.StopXray()
}

// stopRequested fires once the stop file exists. The App uses it to end an
// elevated Core without a second UAC prompt; the Core only checks for the
// file and never writes or deletes it.
func stopRequested(path string) <-chan struct{} {
	done := make(chan struct{})
	if path == "" {
		return done
	}
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := os.Stat(path); err == nil {
				close(done)
				return
			}
		}
	}()
	return done
}

func main() {
	os.Exit(execute(os.Args[1:], run, os.Stdout, os.Stderr))
}
