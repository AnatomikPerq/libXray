package netreport

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// A live run measures the real network, so it only runs on request:
//
//	go test ./netreport -run TestLive -netreport.live -netreport.iface "Ethernet" -netreport.out report.json -v
var (
	liveRun   = flag.Bool("netreport.live", false, "run a live network report")
	liveIface = flag.String("netreport.iface", "", "interface to bind the live run to")
	liveOut   = flag.String("netreport.out", "", "file for the live report JSON")
	liveOnly  = flag.String("netreport.sections", "", "comma-separated sections for the live run")
	liveDNS   = flag.String("netreport.dns", "", "comma-separated system resolvers for the live run")
)

func TestLive(t *testing.T) {
	if !*liveRun {
		t.Skip("live network report: pass -netreport.live")
	}
	request := Request{Interface: *liveIface, Bypass: true}
	if *liveDNS != "" {
		request.SystemDNS = strings.Split(*liveDNS, ",")
	}
	if *liveOnly != "" {
		for _, section := range strings.Split(*liveOnly, ",") {
			request.Sections = append(request.Sections, Section(section))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	report, err := Run(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(report, "", "  ")
	if *liveOut != "" {
		if err := os.WriteFile(*liveOut, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(summary(report))
}

func summary(report *Report) string {
	var out strings.Builder
	fmt.Fprintf(&out, "\nduration %d ms %v\n", report.Duration, report.Timings)
	if network := report.Network; network != nil {
		if network.Interface != nil {
			fmt.Fprintf(&out, "interface %s (%s) kind=%s mtu=%d dns=%v\n", network.Interface.Name,
				network.Interface.Description, network.Interface.Kind, network.Interface.MTU, network.Interface.DNS)
		}
		for _, external := range []*External{network.IPv4, network.IPv6} {
			if external != nil {
				fmt.Fprintf(&out, "external %s AS%d %s %s %s %s\n", external.IP, external.ASN, external.Holder,
					external.Country, external.City, external.Lookup)
			}
		}
	}
	if report.DNS != nil {
		fmt.Fprintf(&out, "port53Intercepted=%v\n", report.DNS.Port53Intercepted)
		for _, resolver := range report.DNS.Resolvers {
			fmt.Fprintf(&out, "dns %-10s %-15s %s rtt=%d loss=%d%% intercepted=%v", resolver.ID, resolver.Address,
				resolver.Status, resolver.RttMs, resolver.LossPct, resolver.Intercepted)
			if resolver.Egress != nil {
				fmt.Fprintf(&out, " egress=%s/%s", resolver.Egress.IP, resolver.Egress.Holder)
			}
			if resolver.DoH != nil {
				fmt.Fprintf(&out, " doh=%s", resolver.DoH.Status)
			}
			out.WriteString("\n   ")
			for _, name := range resolver.Names {
				if name.Status != StatusOK {
					fmt.Fprintf(&out, " %s=%s", name.Name, name.Status)
				}
			}
			out.WriteString("\n")
		}
	}
	for _, site := range report.Sites {
		fmt.Fprintf(&out, "site %-14s %-12s dns=%-8s tcp=%-8s tls=%-12s", site.ID, site.Verdict, site.DNS, site.TCP.Status, site.TLS.Status)
		if site.NoSNI != nil {
			fmt.Fprintf(&out, " nosni=%s rnd=%s", site.NoSNI.Status, site.RandomSNI.Status)
		}
		if site.Split != nil {
			fmt.Fprintf(&out, " split=%s", site.Split.Status)
		}
		if site.Fragment != nil {
			fmt.Fprintf(&out, " fragment=%s", site.Fragment.Status)
		}
		if site.FragmentTransfer != nil {
			fmt.Fprintf(&out, "/%s %dB", site.FragmentTransfer.Status, site.FragmentTransfer.Bytes)
		}
		if site.HTTP != nil {
			fmt.Fprintf(&out, " http=%d %s %dB rx=%d %dKB/s", site.HTTP.HTTP, site.HTTP.Status, site.HTTP.Bytes, site.HTTP.RxBytes, site.HTTP.KBps)
		}
		if site.QUIC != nil {
			fmt.Fprintf(&out, " quic=%s", site.QUIC.Status)
		}
		out.WriteString("\n")
	}
	for _, hosting := range report.Hosting {
		fmt.Fprintf(&out, "host %-13s %-12s tcp=%-8s tls=%-10s", hosting.ID, hosting.Verdict, hosting.TCP.Status, hosting.TLS.Status)
		if hosting.NoSNI != nil {
			fmt.Fprintf(&out, " nosni=%s rnd=%s", hosting.NoSNI.Status, hosting.RandomSNI.Status)
		}
		if hosting.Transfer != nil {
			fmt.Fprintf(&out, " get=%s %dB rx=%d %dKB/s", hosting.Transfer.Status, hosting.Transfer.Bytes, hosting.Transfer.RxBytes, hosting.Transfer.KBps)
		}
		if hosting.WhiteSNI != nil {
			fmt.Fprintf(&out, " white(%s)=%s", hosting.WhiteName, hosting.WhiteSNI.Status)
		}
		if hosting.Split != nil {
			fmt.Fprintf(&out, " split=%s", hosting.Split.Status)
		}
		if hosting.Fragment != nil {
			fmt.Fprintf(&out, " fragment=%s", hosting.Fragment.Status)
		}
		if hosting.FragmentTransfer != nil {
			fmt.Fprintf(&out, "/%s %dB", hosting.FragmentTransfer.Status, hosting.FragmentTransfer.Bytes)
		}
		if hosting.WhiteTransfer != nil {
			fmt.Fprintf(&out, " wget=%s %dB", hosting.WhiteTransfer.Status, hosting.WhiteTransfer.Bytes)
		}
		out.WriteString("\n")
	}
	if report.SNI != nil {
		fmt.Fprintf(&out, "sni filtered=%v passed=%v failed=%v\n", report.SNI.Filtered, report.SNI.Passed, report.SNI.Failed)
	}
	if report.UDP != nil {
		for _, stun := range report.UDP.STUN {
			fmt.Fprintf(&out, "stun %-10s %s %dms\n", stun.ID, stun.Status, stun.Ms)
		}
		for _, quic := range report.UDP.QUIC {
			fmt.Fprintf(&out, "quic %-10s %s %dms %s\n", quic.ID, quic.Status, quic.Ms, quic.Detail)
		}
		if report.UDP.SymmetricNAT != nil {
			fmt.Fprintf(&out, "symmetricNat=%v\n", *report.UDP.SymmetricNAT)
		}
	}
	if report.Facts != nil {
		raw, _ := json.Marshal(report.Facts)
		fmt.Fprintf(&out, "facts %s\n", raw)
	}
	return out.String()
}
