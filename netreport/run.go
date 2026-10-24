package netreport

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
)

// Progress counts finished checks; Total grows as sections start.
type Progress struct {
	Section Section `json:"section,omitempty"`
	Done    int     `json:"done"`
	Total   int     `json:"total"`
}

// run is one report in progress; snapshot is safe to call from any
// goroutine while it runs.
type run struct {
	mu       sync.Mutex
	report   Report
	progress Progress
	finished bool
	err      string
}

func (r *run) update(change func(*Report)) {
	r.mu.Lock()
	change(&r.report)
	r.mu.Unlock()
}

func (r *run) step(section Section, done, total int) {
	r.mu.Lock()
	if section != "" {
		r.progress.Section = section
	}
	r.progress.Done += done
	r.progress.Total += total
	r.mu.Unlock()
}

type Snapshot struct {
	Running  bool            `json:"running"`
	Progress Progress        `json:"progress"`
	Error    string          `json:"error,omitempty"`
	Report   json.RawMessage `json:"report"`
}

func (r *run) snapshot() (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := json.Marshal(&r.report)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Running: !r.finished, Progress: r.progress, Error: r.err, Report: raw}, nil
}

// Run measures the network and returns the finished report.
func Run(ctx context.Context, request Request) (*Report, error) {
	r := &run{}
	if err := r.execute(ctx, request); err != nil {
		return nil, err
	}
	return &r.report, nil
}

func (r *run) execute(ctx context.Context, request Request) error {
	cat, err := defaultCatalog()
	if err != nil {
		return err
	}
	sections := request.Sections
	if len(sections) == 0 {
		sections = allSections
	}
	wants := func(section Section) bool { return slices.Contains(sections, section) }
	started := time.Now()
	r.update(func(report *Report) {
		report.Version = Version
		report.Started = started.UTC()
		report.Interface = request.Interface
		report.Timings = map[Section]int64{}
	})
	timed := func(section Section, work func()) {
		start := time.Now()
		work()
		r.update(func(report *Report) { report.Timings[section] = since(start) })
	}
	p := newProber(ctx, request, cat)
	defer p.http.CloseIdleConnections()

	info := p.prepareNetwork(request.Interface, request.SystemDNS)
	if wants(SectionNetwork) {
		r.step(SectionNetwork, 0, 1)
		timed(SectionNetwork, func() {
			p.runNetwork(ctx, info, func(network *Network) {
				r.update(func(report *Report) { report.Network = network })
			})
		})
		r.step("", 1, 0)
	}
	if wants(SectionDNS) && ctx.Err() == nil {
		r.step(SectionDNS, 0, 1)
		timed(SectionDNS, func() {
			p.runDNS(ctx, func(result *DNSReport) {
				r.update(func(report *Report) { report.DNS = result })
			})
		})
		r.step("", 1, 0)
	}
	if (wants(SectionSites) || wants(SectionHosting)) && ctx.Err() == nil {
		timed("sni", func() {
			p.runSNI(ctx, func(result *SNIReport) {
				r.update(func(report *Report) { report.SNI = result })
			})
		})
	}
	if wants(SectionSites) && ctx.Err() == nil {
		entries := slices.Clone(cat.Sites)
		for _, host := range request.Sites {
			host = strings.TrimSpace(strings.ToLower(host))
			if host != "" {
				entries = append(entries, siteEntry{ID: "custom:" + host, Name: host, Group: "custom", Host: host})
			}
		}
		r.step(SectionSites, 0, len(entries))
		results := make([]SiteResult, len(entries))
		start := time.Now()
		parallel(ctx, len(entries), 10, func(index int) {
			result := p.checkSite(ctx, entries[index])
			result.Custom = entries[index].Group == "custom"
			r.update(func(report *Report) {
				results[index] = result
				report.Sites = completed(results)
			})
			r.step("", 1, 0)
		})
		r.update(func(report *Report) { report.Timings[SectionSites] = since(start) })
	}
	if wants(SectionHosting) && ctx.Err() == nil {
		r.step(SectionHosting, 0, len(cat.Hosting))
		results := make([]HostingResult, len(cat.Hosting))
		start := time.Now()
		// Few at a time: these measure throughput.
		parallel(ctx, len(cat.Hosting), 4, func(index int) {
			result := p.checkHosting(ctx, cat.Hosting[index])
			r.update(func(report *Report) {
				results[index] = result
				report.Hosting = completedHosting(results)
			})
			r.step("", 1, 0)
		})
		r.update(func(report *Report) { report.Timings[SectionHosting] = since(start) })
	}
	if wants(SectionUDP) && ctx.Err() == nil {
		r.step(SectionUDP, 0, 1)
		timed(SectionUDP, func() {
			p.runUDP(ctx, func(result *UDPReport) {
				r.update(func(report *Report) { report.UDP = result })
			})
		})
		r.step("", 1, 0)
	}
	r.update(func(report *Report) {
		report.Duration = since(started)
		report.Facts = deriveFacts(report)
	})
	return ctx.Err()
}

func parallel(ctx context.Context, count, limit int, work func(int)) {
	slots := make(chan struct{}, limit)
	var wait sync.WaitGroup
	for index := range count {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wait.Go(func() {
			defer func() { <-slots }()
			work(index)
		})
	}
	wait.Wait()
}

// completed keeps the catalog order and leaves out checks still running.
func completed(results []SiteResult) []SiteResult {
	var done []SiteResult
	for _, result := range results {
		if result.Verdict != "" {
			done = append(done, result)
		}
	}
	return done
}

func completedHosting(results []HostingResult) []HostingResult {
	var done []HostingResult
	for _, result := range results {
		if result.Verdict != "" {
			done = append(done, result)
		}
	}
	return done
}
