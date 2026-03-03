// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package radius

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/aglants/pcaptool/progress"
)

// IMSIIndex maps IP -> []SessionWindow (sorted, coalesced).
// Lookup(ip, t) returns the IMSI that owned this IP at time t, if any.
type IMSIIndex struct {
	mu   sync.RWMutex
	byIP map[string][]SessionWindow
}

// NewIMSIIndex creates an empty index.
func NewIMSIIndex() *IMSIIndex {
	return &IMSIIndex{
		byIP: make(map[string][]SessionWindow),
	}
}

// Lookup returns the IMSI that owned the given IP at time t, if any.
// Times are matched against [StartMs, EndMs] in SessionWindow.
func (idx *IMSIIndex) Lookup(ip net.IP, t time.Time) (string, bool) {
	if ip == nil {
		return "", false
	}
	ipStr := ip.String()
	if ipStr == "" {
		return "", false
	}

	tsMs := t.UTC().UnixMilli()

	idx.mu.RLock()
	wins := idx.byIP[ipStr]
	idx.mu.RUnlock()

	if len(wins) == 0 {
		return "", false
	}

	// windows are sorted by StartMs and coalesced for (IMSI,IP,SessionID).
	// Small linear scan is fine for our expected cardinalities.
	for _, w := range wins {
		if tsMs < w.StartMs {
			continue
		}
		if w.EndMs > 0 && tsMs > w.EndMs {
			continue
		}
		return w.IMSI, true
	}
	return "", false
}

// BuildIMSIIndexFromPCAPs builds an IP→IMSI session index from the given
// RADIUS Accounting PCAP files.
//
// It reuses the same ingestion pipeline as the Suricata parser project:
//   - processRadiusFile -> radMsg (tsMs, imsi, ip, sid, status, sessTimeSec)
//   - sessionBuilder.ingest -> SessionWindow
//   - closedCoalesced + coalesceSameRunForIndex -> coalesced windows per IP
//
// Differences from the Suricata project:
//   - no streamId / taskId
//   - no Redis (we do a single self-contained pass over the PCAPs)
//   - files[] comes directly from dnsextract (already filtered .pcap list).
func BuildIMSIIndexFromPCAPs(ctx context.Context, files []string) (*IMSIIndex, error) {
	idx := NewIMSIIndex()

	if len(files) == 0 {
		return idx, nil
	}

	collector := NewRadiusCollector(16_384)
	dedup := newDeduper(2*time.Hour, 64)

	type fileResult struct {
		path string
		err  error
	}

	fileCh := make(chan string)
	resCh := make(chan fileResult)

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	// Workers: process each file with processRadiusFile, emit into collector.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for path := range fileCh {
				err := processRadiusFile(ctx, path, collector, dedup)
				resCh <- fileResult{path: path, err: err}
			}
		}()
	}

	// Feeder
	go func() {
		for _, path := range files {
			fileCh <- path
		}
		close(fileCh)
	}()

	// Collector closer
	go func() {
		wg.Wait()
		close(resCh)
	}()

	totalFiles := len(files)
	doneFiles := 0
	var firstErr error

	for res := range resCh {
		doneFiles++
		if res.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("radius: %s: %w", filepath.Base(res.path), res.err)
		}
		// Progress bar: same style as DNS pass, label shows current file basename.
		progress.UpdateBar(doneFiles, totalFiles, "RADIUS "+filepath.Base(res.path))
	}

	if firstErr != nil {
		return nil, firstErr
	}

	// Drain all radius messages and sort deterministically, exactly as in
	// processRadiusDirConcurrent from the Suricata parser.
	msgs := collector.Drain()
	if len(msgs) == 0 {
		// No Accounting messages -> empty index is valid.
		return idx, nil
	}

	sort.Slice(msgs, func(i, j int) bool {
		if msgs[i].tsMs != msgs[j].tsMs {
			return msgs[i].tsMs < msgs[j].tsMs
		}
		if msgs[i].imsi != msgs[j].imsi {
			return msgs[i].imsi < msgs[j].imsi
		}
		if msgs[i].ip != msgs[j].ip {
			return msgs[i].ip < msgs[j].ip
		}
		if msgs[i].sid != msgs[j].sid {
			return msgs[i].sid < msgs[j].sid
		}
		return msgs[i].status < msgs[j].status // Start < Interim < Stop
	})

	// Build session windows with the same logic as your existing code:
	// sessionBuilder.ingest(tsMs, status, imsi, ip, sid, sessTimeSec)
	// handles:
	//   - Start/Interim/Stop
	//   - synthetic opens from Interim / Stop (middle-session pickup)
	//   - backdating from Acct-Session-Time
	//   - "close on new Start" for same IMSI+IP, different SID.
	builder := newSessionBuilder()
	for _, m := range msgs {
		builder.ingest(m.tsMs, m.status, m.imsi, m.ip, m.sid, m.sessTimeSec)
	}

	// Close provisional and stale windows in a self-contained way.
	// Same parameters as your replay finalizer (tailMs=0 => lastSeenMs).
	builder.finalizeForReplay(0, 6*time.Hour, false)

	// Collect closed windows for this pass.
	closed := builder.closedCoalesced()
	if len(closed) == 0 {
		return idx, nil
	}

	// Build IP -> []SessionWindow index, coalesced, as in buildRadiusResolutionIndexInternal.
	byIP := make(map[string][]SessionWindow, 100_000)

	for _, w := range closed {
		if w.IP == "" || w.IMSI == "" {
			continue
		}
		byIP[w.IP] = append(byIP[w.IP], w)
	}

	for ip, wins := range byIP {
		// Ensure StartMs sort for determinism before coalescing.
		sort.Slice(wins, func(i, j int) bool { return wins[i].StartMs < wins[j].StartMs })
		wins = coalesceSameRunForIndex(wins)
		byIP[ip] = wins
	}

	idx.mu.Lock()
	idx.byIP = byIP
	idx.mu.Unlock()

	// Final bar to 100% with a generic label.
	progress.UpdateBar(totalFiles, totalFiles, "RADIUS scan complete")

	return idx, nil
}
