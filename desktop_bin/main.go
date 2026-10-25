//go:build windows || (linux && !android)

package main

import (
	"bytes"
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
	// Engaged before anything else, and left in place on every error: the App
	// decides whether a failed start keeps the block (a reconnect) or lifts it
	// (a first connect).
	var guard *killSwitchGuard
	if options.killSwitch {
		if guard, err = engageKillSwitch(options, config); err != nil {
			return err
		}
		// Unless asked to survive a reboot, the block ends with the session:
		// fast startup would otherwise carry it over a shutdown. Without the
		// watch the App still lifts it once it sees the new session.
		if !options.killSwitchPersistent {
			_ = watchSessionEnd(func() { _ = liftKillSwitch() })
		}
	}
	if options.interfaceName != "" {
		if options.dns == dns.NetworkDNS {
			// The resolver the interface itself is configured with, as every
			// app uses it without the VPN; a fixed public one lost a quarter
			// of fresh-socket queries on the owner's home network.
			if _, err := dns.SetNetworkDNS(options.interfaceName, fallbackDNS); err != nil {
				return err
			}
		} else if err := dns.SetDNS(options.dns, options.interfaceName); err != nil {
			return err
		}
		defer dns.ResetDNS()
	}

	if err := xray.RunXray(string(config)); err != nil {
		return err
	}
	if guard != nil {
		if err := guard.admitTunnel(); err != nil {
			xray.StopXray()
			return err
		}
	}
	// Only now is the connection usable; the App reports it connected once
	// this is written.
	if options.ready != nil {
		if err := options.ready(); err != nil {
			xray.StopXray()
			return err
		}
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	reason := stopSignal
	select {
	case <-signals:
	case reason = <-stopRequested(options.stopFile):
	}
	err = xray.StopXray()
	if guard != nil && reason == stopDisconnect {
		if liftErr := liftKillSwitch(); err == nil {
			err = liftErr
		}
	}
	return err
}

type stopReason int

const (
	// stopSignal: interrupted, or the session ends. The user did not
	// disconnect, so the kill switch stays.
	stopSignal stopReason = iota
	// stopDisconnect: the App disconnects; the kill switch is lifted.
	stopDisconnect
	// stopRestart: the App replaces this Core with another one; the kill
	// switch stays, so nothing slips out in between.
	stopRestart
)

// fallbackDNS answers the Core's own lookups when the interface has no
// resolver of its own that answers (owner's decision of 25.10.2026).
const fallbackDNS = "1.1.1.1:53"

// restartRequest is what the App writes into the stop file when another Core
// follows. An empty file, as older Apps create it, means a disconnect.
var restartRequest = []byte("restart")

// stopRequested fires once the stop file exists. The App uses it to end an
// elevated Core without a second UAC prompt; the Core only reads the file and
// never writes or deletes it.
func stopRequested(path string) <-chan stopReason {
	done := make(chan stopReason, 1)
	if path == "" {
		return done
	}
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			content, err := os.ReadFile(path)
			if err == nil || !os.IsNotExist(err) {
				done <- readStopReason(content)
				return
			}
		}
	}()
	return done
}

func readStopReason(content []byte) stopReason {
	if bytes.Equal(bytes.TrimSpace(content), restartRequest) {
		return stopRestart
	}
	return stopDisconnect
}

func main() {
	os.Exit(execute(os.Args[1:], run, os.Stdout, os.Stderr))
}
