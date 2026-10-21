//go:build windows || (linux && !android)

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/xtls/libxray/killswitch"
)

// liftKillSwitch is replaced in tests.
var liftKillSwitch = killswitch.Lift

// killSwitchGuard holds the kill switch of a TUN Core. It engages before Xray
// starts, so that nothing slips out while the tunnel comes up, and lets the
// tunnel's own traffic through once Xray has created the adapter.
type killSwitchGuard struct {
	options killswitch.Options
	tunName string
}

func engageKillSwitch(run runOptions, config []byte) (*killSwitchGuard, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	apps := []string{self}
	if run.killSwitchApp != "" {
		apps = append(apps, run.killSwitchApp)
	}
	guard := &killSwitchGuard{
		options: killswitch.Options{
			Apps:       apps,
			AllowLAN:   run.killSwitchLAN,
			Persistent: run.killSwitchPersistent,
		},
		tunName: tunInboundName(config),
	}
	if guard.tunName == "" {
		return nil, errors.New("kill switch: the config has no named TUN inbound")
	}
	if err := killswitch.Engage(guard.options); err != nil {
		return nil, fmt.Errorf("kill switch: %w", err)
	}
	return guard, nil
}

// admitTunnel lets the traffic of the TUN adapter Xray has just created pass.
func (g *killSwitchGuard) admitTunnel() error {
	luid, err := interfaceLUID(g.tunName)
	if err != nil {
		return fmt.Errorf("kill switch: TUN adapter %s: %w", g.tunName, err)
	}
	g.options.TunLUID = luid
	if err := killswitch.Engage(g.options); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	return nil
}

// tunInboundName returns the adapter name of the config's TUN inbound. Xray
// picks a free name itself when there is none, which the guard cannot know;
// the App always sets one.
func tunInboundName(config []byte) string {
	var parsed struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Name string `json:"name"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil {
		return ""
	}
	for _, inbound := range parsed.Inbounds {
		if inbound.Protocol == "tun" {
			return inbound.Settings.Name
		}
	}
	return ""
}
