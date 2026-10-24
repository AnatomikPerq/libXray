package netreport

// Facts sum the report up for the App's verdicts; every fact names the
// checks it comes from, so a reader can verify it.
type Facts struct {
	// Mode is "open" (nothing blocked), "filtered" (some services blocked),
	// "whitelist" (only allowed networks answer at all: a white list by
	// address, past which not even a VPN server connects), "sni_whitelist"
	// (the addresses answer, but DPI passes only allowed server names) or
	// "offline".
	Mode string `json:"mode"`
	// SNIFiltering: a made-up TLS name fails where no name passes.
	SNIFiltering bool `json:"sniFiltering,omitempty"`
	// WhitelistBySNI: allowed names open addresses that other names cannot.
	WhitelistBySNI bool     `json:"whitelistBySni,omitempty"`
	DNSSpoofing    []string `json:"dnsSpoofing,omitempty"`
	DNSInjection   bool     `json:"dnsInjection,omitempty"`
	DNSIntercepted []string `json:"dnsIntercepted,omitempty"`
	DNSLossy       []string `json:"dnsLossy,omitempty"`
	BlockedSites   []string `json:"blockedSites,omitempty"`
	GeoBlocked     []string `json:"geoBlocked,omitempty"`
	Frozen         []string `json:"frozen,omitempty"`
	BlockedHosting []string `json:"blockedHosting,omitempty"`
	OpenHosting    []string `json:"openHosting,omitempty"`
	// SplitHelps and FragmentHelps list refused sites and providers
	// ("hosting:" ids) the cut-up ClientHello got through to; BypassTried
	// counts the refusals both were tried on.
	SplitHelps    []string `json:"splitHelps,omitempty"`
	FragmentHelps []string `json:"fragmentHelps,omitempty"`
	BypassTried   int      `json:"bypassTried,omitempty"`
	// UDP and QUIC are "ok", "partial" or "blocked" over their targets.
	UDP  Status `json:"udp,omitempty"`
	QUIC Status `json:"quic,omitempty"`
}

const lossyPct = 20

func usable(verdict Status) bool {
	switch verdict {
	case StatusOK, StatusDNSOnly, StatusGeo, StatusSlow:
		return true
	}
	return false
}

func deriveFacts(report *Report) *Facts {
	facts := &Facts{}
	if report.DNS != nil {
		for _, resolver := range report.DNS.Resolvers {
			spoofed := false
			for _, name := range resolver.Names {
				switch name.Status {
				case StatusInjected:
					facts.DNSInjection = true
					spoofed = true
				case StatusSpoofed, StatusNXDomain, StatusEmpty:
					spoofed = true
				}
			}
			if spoofed {
				facts.DNSSpoofing = append(facts.DNSSpoofing, resolver.ID)
			}
			if resolver.Intercepted {
				facts.DNSIntercepted = append(facts.DNSIntercepted, resolver.ID)
			}
			if resolver.Status == StatusOK && resolver.LossPct >= lossyPct {
				facts.DNSLossy = append(facts.DNSLossy, resolver.ID)
			}
		}
	}

	whitelistOpen, regularOpen, regularTotal, anyOpen := 0, 0, 0, false
	// A closed regular site whose address still answered another name,
	// none, or a cut-up hello: the filter is on names, not addresses.
	regularAnswers := false
	for _, site := range report.Sites {
		open := usable(site.Verdict)
		anyOpen = anyOpen || open
		switch {
		case site.Verdict == StatusGeo:
			facts.GeoBlocked = append(facts.GeoBlocked, site.ID)
		case site.Verdict == StatusFrozen:
			facts.Frozen = append(facts.Frozen, site.ID)
			facts.BlockedSites = append(facts.BlockedSites, site.ID)
		case !open && site.Verdict != StatusError:
			facts.BlockedSites = append(facts.BlockedSites, site.ID)
		}
		facts.noteBypass(site.ID, site.Split, site.Fragment, site.FragmentTransfer)
		if siteIsWhitelistControl(site.ID) && open {
			whitelistOpen++
		}
		if siteIsRegular(site.ID) {
			regularTotal++
			for _, step := range []*Step{site.NoSNI, site.RandomSNI, site.WhiteSNI, site.Fragment} {
				regularAnswers = regularAnswers || step != nil && reached(step.Status)
			}
			if open {
				regularOpen++
			}
		}
	}

	for _, hosting := range report.Hosting {
		facts.noteBypass("hosting:"+hosting.ID, hosting.Split, hosting.Fragment, hosting.FragmentTransfer)
		switch {
		case hosting.Verdict == StatusOK || hosting.Verdict == StatusSlow:
			facts.OpenHosting = append(facts.OpenHosting, hosting.ID)
		case hosting.Verdict != StatusError:
			facts.BlockedHosting = append(facts.BlockedHosting, hosting.ID)
			if hosting.Verdict == StatusFrozen {
				facts.Frozen = append(facts.Frozen, "hosting:"+hosting.ID)
			}
		}
	}

	if report.SNI != nil {
		facts.SNIFiltering = report.SNI.Filtered
		facts.WhitelistBySNI = report.SNI.Filtered && len(report.SNI.Passed) > 0
	}

	switch {
	case len(report.Sites) == 0:
		facts.Mode = ""
	case !anyOpen:
		facts.Mode = "offline"
	// As dpi-ch's CIDR white list check: allowed services open, ordinary
	// foreign ones not. Providers stay out of it: under a white list one of
	// them now and then lets a connection through.
	case whitelistOpen > 0 && regularTotal > 0 && regularOpen == 0:
		if regularAnswers || facts.WhitelistBySNI {
			facts.Mode = "sni_whitelist"
		} else {
			facts.Mode = "whitelist"
		}
	case len(facts.BlockedSites) > 0 || len(facts.DNSSpoofing) > 0:
		facts.Mode = "filtered"
	default:
		facts.Mode = "open"
	}

	if report.UDP != nil {
		ok, total := 0, 0
		for _, stun := range report.UDP.STUN {
			if stun.Status != StatusError {
				total++
				if stun.Status == StatusOK {
					ok++
				}
			}
		}
		facts.UDP = share(ok, total)
		ok, total = 0, 0
		for _, quic := range report.UDP.QUIC {
			if quic.Status != StatusError {
				total++
				if reached(quic.Status) {
					ok++
				}
			}
		}
		facts.QUIC = share(ok, total)
	}
	return facts
}

func (facts *Facts) noteBypass(id string, split, fragment *Step, transfer *Transfer) {
	if split == nil && fragment == nil {
		return
	}
	facts.BypassTried++
	if bypassWorks(split, nil) {
		facts.SplitHelps = append(facts.SplitHelps, id)
	}
	if bypassWorks(fragment, transfer) {
		facts.FragmentHelps = append(facts.FragmentHelps, id)
	}
}

func share(ok, total int) Status {
	switch {
	case total == 0:
		return ""
	case ok == total:
		return StatusOK
	case ok == 0:
		return "blocked"
	}
	return "partial"
}

func siteIsWhitelistControl(id string) bool {
	cat, err := defaultCatalog()
	if err != nil {
		return false
	}
	for _, site := range cat.Sites {
		if site.ID == id {
			return site.Whitelist
		}
	}
	return false
}

func siteIsRegular(id string) bool {
	cat, err := defaultCatalog()
	if err != nil {
		return false
	}
	for _, site := range cat.Sites {
		if site.ID == id {
			return site.Regular
		}
	}
	return false
}
