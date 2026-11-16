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
	"net/netip"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/aglants/pcaptool/progress"
)

// IMSIIndex maps IP -> []SessionWindow sorted by start time.
// Lookup(ip, t) returns the IMSI that owned this IP at time t, if any.
type IMSIIndex struct {
	byIP map[netip.Addr][]SessionWindow
}

// NewIMSIIndex creates an empty index.
func NewIMSIIndex() *IMSIIndex {
	return &IMSIIndex{
		byIP: make(map[netip.Addr][]SessionWindow),
	}
}

// Lookup returns the IMSI that owned the given IP at time t, if any.
// Times are matched against [StartMs, EndMs] in SessionWindow.
func (idx *IMSIIndex) Lookup(ip net.IP, t time.Time) (string, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	return idx.LookupAddr(addr.Unmap(), t)
}

// LookupAddr resolves a packet address without allocating a string. The index
// is immutable after construction and safe for concurrent readers. Conflicting
// IMSIs at the observation time produce an unresolved identity.
func (idx *IMSIIndex) LookupAddr(ip netip.Addr, t time.Time) (string, bool) {
	if idx == nil {
		return "", false
	}
	tsMs := t.UTC().UnixMilli()
	imsi := ""
	for _, w := range idx.byIP[ip.Unmap()] {
		if w.StartMs > tsMs {
			break
		}
		if tsMs > w.EndMs {
			continue
		}
		if imsi != "" && imsi != w.IMSI {
			return "", false
		}
		imsi = w.IMSI
	}
	return imsi, imsi != ""
}

// BuildIMSIIndexFromPCAPs builds an IP→IMSI session index from the given
// RADIUS Accounting PCAP files.
//
// All accounting packets are scanned independently of fleet admission. Records
// are sorted before deduplication and session construction, so worker/file order
// cannot choose an IP owner. A read failure never returns a partial index.
func BuildIMSIIndexFromPCAPs(ctx context.Context, files []string) (*IMSIIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idx := NewIMSIIndex()

	if len(files) == 0 {
		return idx, nil
	}

	collector := NewRadiusCollector(16_384)

	type fileResult struct {
		path string
		err  error
	}

	fileCh := make(chan string)
	resCh := make(chan fileResult)

	workers := min(runtime.GOMAXPROCS(0), len(files))
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
				err := processRadiusFile(ctx, path, collector)
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

	if err := ctx.Err(); err != nil {
		return nil, err
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
		if msgs[i].status != msgs[j].status {
			return msgs[i].status < msgs[j].status
		}
		if msgs[i].sessTimeSec != msgs[j].sessTimeSec {
			return msgs[i].sessTimeSec < msgs[j].sessTimeSec
		}
		if msgs[i].hasSessionTime != msgs[j].hasSessionTime {
			return !msgs[i].hasSessionTime
		}
		return msgs[i].dedupKey < msgs[j].dedupKey
	})

	dedup := newDeduper(2*time.Hour, 64)
	retained := msgs[:0]
	for _, m := range msgs {
		if !dedup.Seen(m.dedupKey, time.UnixMilli(m.tsMs)) {
			retained = append(retained, m)
		}
	}
	windows := buildSessionWindows(retained, collector.captureEnd.UTC().UnixMilli())
	for _, w := range windows {
		ip, err := netip.ParseAddr(w.IP)
		if err != nil {
			continue
		}
		idx.byIP[ip.Unmap()] = append(idx.byIP[ip.Unmap()], w)
	}

	// Final bar to 100% with a generic label.
	progress.UpdateBar(totalFiles, totalFiles, "RADIUS scan complete")

	return idx, nil
}

// AddressCount reports index coverage without exposing subscriber identifiers.
func (idx *IMSIIndex) AddressCount() int { return len(idx.byIP) }
