// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/aglants/pcaptool/progress"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var debugDNSFallback = os.Getenv("PCAPTOOL_DEBUG_DNS_FALLBACK") != ""

func debugDNSFallbackf(format string, args ...any) {
	if !debugDNSFallback {
		return
	}
	// Keep it grep-friendly and line-oriented.
	fmt.Fprintf(os.Stderr, "[dns-fallback] "+format+"\n", args...)
}

const (
	maxConnDelay       = 5 * time.Second // or tune as you like
	maxCandidatesPerTX = 8               // safety guard
)

// FirstPacketInfo describes the earliest packet observed while processing PCAPs.
type FirstPacketInfo struct {
	Timestamp time.Time
	PCAPFile  string
}

// BuildTransactionsFromPCAPs:
// Pass 1 – scan all PCAPs for DNS A queries/responses and build DNSTransactions.
// Returns slice of transactions and earliest packet timestamp (for filename).
// BuildTransactionsFromPCAPs runs Pass 1 (DNS) in parallel over files.
func BuildTransactionsFromPCAPs(ctx context.Context, files []string) ([]*DNSTransaction, time.Time, error) {
	type fileResult struct {
		txMap    map[TxKey][]*DNSTransaction
		earliest time.Time
		err      error
	}

	fileCh := make(chan string)
	resCh := make(chan fileResult)

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	totalFiles := len(files)

	// Worker goroutines
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()

			for path := range fileCh {
				txMap, earliest, err := scanDNSInFile(ctx, path)
				resCh <- fileResult{
					txMap:    txMap,
					earliest: earliest,
					err:      err,
				}
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

	// Collector
	go func() {
		wg.Wait()
		close(resCh)
	}()

	var (
		globalMap      = make(map[TxKey][]*DNSTransaction)
		globalEarliest time.Time
		first          = true
		doneFiles      = 0
	)

	for res := range resCh {
		if res.err != nil {
			return nil, time.Time{}, res.err
		}
		doneFiles++
		progress.UpdateBar(doneFiles, totalFiles, "DNS "+filepath.Base(files[doneFiles-1]))

		// Merge earliest timestamp
		if !res.earliest.IsZero() && (first || res.earliest.Before(globalEarliest)) {
			globalEarliest = res.earliest
			first = false
		}

		// Merge txMaps by TxKey while preserving distinct per-key query instances.
		for k, localList := range res.txMap {
			if len(localList) == 0 {
				continue
			}
			bucket := globalMap[k]
			for _, localTx := range localList {
				bucket = mergeDNSTransactionIntoBucket(bucket, localTx)
			}
			sortTxBucketByTime(bucket)
			globalMap[k] = bucket
		}
	}

	// Convert globalMap to slice
	var txs []*DNSTransaction
	for _, bucket := range globalMap {
		txs = append(txs, bucket...)
	}

	// Sort by request time
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].RequestTime.Before(txs[j].RequestTime)
	})

	// Final bar to 100%
	progress.UpdateBar(totalFiles, totalFiles, "DNS scan complete")

	return txs, globalEarliest, nil
}

// helper: for a sorted slice of txs, find the last one with RequestTime <= ts
func findLatestTxBefore(txs []*DNSTransaction, ts time.Time) *DNSTransaction {
	if len(txs) == 0 {
		return nil
	}
	i := sort.Search(len(txs), func(i int) bool {
		return !txs[i].RequestTime.Before(ts) // RequestTime >= ts
	})
	if i == 0 {
		return nil
	}
	return txs[i-1]
}

// pickFallbackTxUniq attempts an issuer-only fallback match in [ts-win, ts] but only if it is safe.
//
// HARDENED safety policy (to prevent cross-name IP poisoning):
//   - Only succeed if there is exactly ONE *unresolved* eligible tx in the window.
//   - Any ambiguity (0 or >1 unresolved eligible txs) returns nil.
//
// Returns (chosenTx, eligibleCount, unresolvedCount) for debug visibility.
func pickFallbackTxUniq(txs []*DNSTransaction, ts time.Time, win time.Duration) (*DNSTransaction, int, int) {
	if len(txs) == 0 {
		return nil, 0, 0
	}
	start := ts.Add(-win)

	lo := sort.Search(len(txs), func(i int) bool {
		return !txs[i].RequestTime.Before(start)
	})
	hi := sort.Search(len(txs), func(i int) bool {
		return txs[i].RequestTime.After(ts)
	})
	if lo >= hi {
		return nil, 0, 0
	}

	var (
		lastEligible     *DNSTransaction
		chosenUnresolved *DNSTransaction
		eligibleCount    int
		unresCount       int
	)

	for i := lo; i < hi; i++ {
		tx := txs[i]
		if tx == nil {
			continue
		}

		// Defensive: ignore finalized txs (issuerTxs should already skip these).
		if tx.DestinationPort != nil && *tx.DestinationPort > 0 {
			continue
		}
		// Defensive: only allow resolvable-looking names.
		if !LooksLikeResolvableDNSName(tx.DNSName) {
			continue
		}

		eligibleCount++
		lastEligible = tx

		if len(tx.ResolvedIPs) == 0 {
			unresCount++
			chosenUnresolved = tx
			if unresCount > 1 {
				// early exit: ambiguous
				return nil, eligibleCount, unresCount
			}
		}
	}

	// HARDENED: require exactly one unresolved tx in the window.
	if unresCount == 1 {
		return chosenUnresolved, eligibleCount, unresCount
	}

	// Keep lastEligible unused except for debug counts above; ambiguity => nil.
	_ = lastEligible
	return nil, eligibleCount, unresCount
}

// AttachConnectionsAndCollectEdgesFromPCAPs runs the existing DNS→connection correlation
// logic (Pass 3) and, in the same scan, collects ground-truth connectivity edges.
//
// Edges are deduped by (issuerIP, dstIP, protocol, port) and are IPv4-only.
// DNS attribution is joined later when building the topology matrix.
//
// This function is intentionally file-parallel. Each worker builds a local edge set
// and the main goroutine merges the per-file edge slices to avoid lock contention.
func AttachConnectionsAndCollectEdgesFromPCAPs(
	ctx context.Context,
	files []string,
	txs []*DNSTransaction,
	onlyTCP bool,
	excludePorts map[uint16]struct{},
	enforcePrivateAsSource bool,
) ([]connectivity.Edge, FirstPacketInfo, error) {
	index := BuildTxnIndex(txs)

	// issuer -> txs sorted by RequestTime (for conservative fallback matching)
	issuerTxs := make(map[string][]*DNSTransaction, 4096)
	for _, tx := range txs {
		// Skip already-finalized (e.g., synthetic SNI txs)
		if tx.DestinationPort != nil && *tx.DestinationPort > 0 {
			continue
		}
		if !LooksLikeResolvableDNSName(tx.DNSName) {
			continue
		}
		issuer := tx.IssuerIP.String()
		if issuer == "" {
			continue
		}
		issuerTxs[issuer] = append(issuerTxs[issuer], tx)
	}
	for k := range issuerTxs {
		sort.Slice(issuerTxs[k], func(i, j int) bool {
			return issuerTxs[k][i].RequestTime.Before(issuerTxs[k][j].RequestTime)
		})
	}

	type update struct {
		tx           *DNSTransaction
		cand         ConnCandidate
		usedDst4     net.IP // dst IPv4 actually used by the observed connection
		fromFallback bool   // true if issuer-only fallback matched (no direct issuer+dstIP match)
	}

	updates := make(chan update, 4096)

	// --- DNS correlation aggregator (existing behavior + evidence marking) ---
	var aggWG sync.WaitGroup
	aggWG.Add(1)
	go func() {
		defer aggWG.Done()
		for u := range updates {
			if len(u.tx.Candidates) < maxCandidatesPerTX {
				u.tx.Candidates = append(u.tx.Candidates, u.cand)
			}

			// Defensive: ensure NameEvidence exists so inferred mappings carry "dns" or "sni".
			if u.tx.NameEvidence == EvNone {
				u.tx.NameEvidence = EvDNSAnswer
			}

			// Mark that this dst IP was confirmed by observed connectivity (synack),
			// and if this was a fallback match, allow adding usedDst4 even if tx already
			// has other IPs (CDN case) -> conn+synack (+ NameEvidence).
			if u.usedDst4 != nil {
				if debugDNSFallback && u.fromFallback {
					s := u.usedDst4.String()
					had := false
					for _, rip := range u.tx.ResolvedIPs {
						if rip != nil && rip.To4() != nil && rip.String() == s {
							had = true
							break
						}
					}
					evBefore := EvNone
					if u.tx.ResolvedIPEvidence != nil {
						evBefore = u.tx.ResolvedIPEvidence[s]
					}
					debugDNSFallbackf("before-mark issuer=%s name=%q dst=%s had=%v ev=%s", u.tx.IssuerIP, u.tx.DNSName, s, had, EvidenceString(evBefore))
				}
				ip4 := u.usedDst4.To4()
				if ip4 != nil {
					key := ip4.String()
					had := false
					if u.tx.ResolvedIPEvidence != nil {
						_, had = u.tx.ResolvedIPEvidence[key]
					}
					u.tx.MarkObservedConn(ip4, u.fromFallback)
					if debugDNSFallback && u.fromFallback {
						// If it wasn't known before, this call likely backfilled it.
						now := false
						if u.tx.ResolvedIPEvidence != nil {
							_, now = u.tx.ResolvedIPEvidence[key]
						}
						if !had && now {
							debugDNSFallbackf("backfilled-ip issuer=%s name=%q ip=%s ev=%s", u.tx.IssuerIP, u.tx.DNSName, key, EvidenceString(u.tx.ResolvedIPEvidence[key]))
						}
					}
				}
			}
		}
	}()

	// --- Topology edge aggregation (new behavior) ---
	type edgeBatch struct {
		fileIdx int
		edges   []connectivity.Edge
	}
	edgeCh := make(chan edgeBatch, 256)

	// Worker pool over files
	totalFiles := len(files)
	if totalFiles == 0 {
		close(updates)
		aggWG.Wait()
		return nil, FirstPacketInfo{}, nil
	}

	edgeBatches := make([][]connectivity.Edge, totalFiles)
	var edgeAggWG sync.WaitGroup
	edgeAggWG.Add(1)
	go func() {
		defer edgeAggWG.Done()
		for b := range edgeCh {
			edgeBatches[b.fileIdx] = b.edges
		}
	}()

	workers := runtime.GOMAXPROCS(0)
	if workers > totalFiles {
		workers = totalFiles
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)

	var firstErr error
	var errMu sync.Mutex

	var firstPkt FirstPacketInfo
	var firstPktMu sync.Mutex

	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	setFirstPacket := func(ts time.Time, file string) {
		if ts.IsZero() {
			return
		}
		ts = ts.UTC()
		firstPktMu.Lock()
		if firstPkt.Timestamp.IsZero() || ts.Before(firstPkt.Timestamp) {
			firstPkt.Timestamp = ts
			firstPkt.PCAPFile = file
		}
		firstPktMu.Unlock()
	}

	var filesDone int64

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			// Respect context cancellation
			select {
			case <-ctx.Done():
				setErr(ctx.Err())
				return
			default:
			}

			path := files[idx]

			handle, err := pcap.OpenOffline(path)
			if err != nil {
				setErr(fmt.Errorf("open pcap %s: %w", path, err))
				return
			}

			// One collector per file (no locks); merged after file completes.
			opt := connectivity.DefaultOptions()
			opt.ExcludedDstPorts = excludePorts
			opt.EnforcePrivateAsSource = enforcePrivateAsSource

			coll := connectivity.NewCollector(opt)

			source := gopacket.NewPacketSource(handle, handle.LinkType())
			source.NoCopy = true

			var (
				localEarliest time.Time
				haveLocalTS   bool
			)

			for packet := range source.Packets() {
				select {
				case <-ctx.Done():
					handle.Close()
					setErr(ctx.Err())
					return
				default:
				}

				md := packet.Metadata()
				if md == nil {
					continue
				}
				ts := md.Timestamp
				if !haveLocalTS || ts.Before(localEarliest) {
					localEarliest = ts
					haveLocalTS = true
				}

				// --- NEW: collect topology edges (IPv4-only, per requirements) ---
				coll.OnPacket(packet, ts)

				// --- Existing DNS correlation logic (with safe fallback) ---
				ip4 := packet.Layer(layers.LayerTypeIPv4)
				ip6 := packet.Layer(layers.LayerTypeIPv6)
				if ip4 == nil && ip6 == nil {
					continue
				}

				var srcIPStr, dstIPStr string
				if ip4 != nil {
					ip := ip4.(*layers.IPv4)
					srcIPStr, dstIPStr = ip.SrcIP.String(), ip.DstIP.String()
				} else {
					ip := ip6.(*layers.IPv6)
					srcIPStr, dstIPStr = ip.SrcIP.String(), ip.DstIP.String()
				}

				// Detect connection events: TCP SYN or any UDP (existing heuristic)
				var dstPort uint16
				var proto L4Proto
				isConn := false

				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					if tcp.SYN && !tcp.ACK {
						dstPort = uint16(tcp.DstPort)

						// IMPORTANT: don't correlate DNS itself as the "connection" for DNS transactions.
						// Otherwise resolver IPs (10.4.0.230/240, 8.8.8.8, etc.) get injected into ResolvedIPs.
						if dstPort == 53 {
							continue
						}

						isConn = true
						proto = L4ProtoTCP
					}
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp := udpLayer.(*layers.UDP)
					dstPort = uint16(udp.DstPort)

					// Same rule for UDP DNS queries.
					if dstPort == 53 {
						continue
					}
					if excludePorts != nil {
						if _, ok := excludePorts[dstPort]; ok {
							continue
						}
					}
					isConn = true
					proto = L4ProtoUDP
				}

				if !isConn {
					continue
				}

				k := idxKey{Issuer: srcIPStr, Dst: dstIPStr}
				txsForKey, ok := index[k]

				var (
					tx           *DNSTransaction
					fromFallback bool
				)

				if ok {
					tx = findLatestTxBefore(txsForKey, ts)
				} else {
					// HARDENING #1: never issuer-only fallback for UDP (too ambiguous; causes name poisoning).
					if proto == L4ProtoUDP {
						if debugDNSFallback {
							debugDNSFallbackf("skip-udp-fallback issuer=%s dst=%s:%d ts=%s", srcIPStr, dstIPStr, dstPort, ts.UTC().Format(time.RFC3339Nano))
						}
						continue
					}

					// HARDENING #2: TCP issuer-only fallback only if exactly one unresolved tx exists in window.
					list := issuerTxs[srcIPStr]
					eligibleCnt, unresCnt := 0, 0
					tx, eligibleCnt, unresCnt = pickFallbackTxUniq(list, ts, maxConnDelay)
					if tx == nil {
						// Ambiguous issuer-only window -> do not backfill conn IP into any DNS name.
						if debugDNSFallback {
							debugDNSFallbackf("ambiguous issuer-only issuer=%s dst=%s:%d proto=%s ts=%s eligible=%d unresolved=%d",
								srcIPStr, dstIPStr, dstPort, proto, ts.UTC().Format(time.RFC3339Nano), eligibleCnt, unresCnt)
						}
						continue
					}
					fromFallback = true
					if debugDNSFallback {
						debugDNSFallbackf("fallback-selected issuer=%s name=%q resolver=%v dst=%s:%d proto=%s dt=%s eligible=%d unresolved=%d resolvedIPs=%d",
							srcIPStr, tx.DNSName, tx.ResolverIP, dstIPStr, dstPort, proto, ts.Sub(tx.RequestTime), eligibleCnt, unresCnt, len(tx.ResolvedIPs))
					}
				}

				if tx == nil {
					continue
				}

				dt := ts.Sub(tx.RequestTime)
				if dt < 0 || dt > maxConnDelay {
					if fromFallback && debugDNSFallback {
						debugDNSFallbackf("fallback-outside-window issuer=%s name=%q dst=%s dt=%s max=%s",
							srcIPStr, tx.DNSName, dstIPStr, dt, maxConnDelay)
					}
					continue
				}

				// Actually-used dst IPv4 (for synack marking + optional backfill).
				var usedDst4 net.IP
				if ip := net.ParseIP(dstIPStr); ip != nil {
					usedDst4 = ip.To4()
				}

				// Send candidate to aggregator
				select {
				case <-ctx.Done():
					handle.Close()
					setErr(ctx.Err())
					return
				case updates <- update{
					tx: tx,
					cand: ConnCandidate{
						Port:  dstPort,
						DT:    dt,
						Proto: proto,
					},
					usedDst4:     usedDst4,
					fromFallback: fromFallback,
				}:
				}
			}

			handle.Close()
			if haveLocalTS {
				setFirstPacket(localEarliest, filepath.Base(path))
			}

			// NEW: emit per-file unique edges to global edge aggregator.
			edgeCh <- edgeBatch{fileIdx: idx, edges: coll.EdgesByFirstSeen()}

			// Progress update (files completed)
			done := int(atomic.AddInt64(&filesDone, 1))
			progress.UpdateBar(done, totalFiles, "connections "+filepath.Base(path))
		}
	}

	for i := 0; i < workers; i++ {
		go worker()
	}

	for i := range files {
		jobs <- i
	}
	close(jobs)

	// Wait for workers and aggregators
	wg.Wait()

	close(updates)
	aggWG.Wait()

	close(edgeCh)
	edgeAggWG.Wait()

	if firstErr != nil {
		return nil, FirstPacketInfo{}, firstErr
	}

	// Choose closest candidate (min dt) per DNS transaction (existing behavior)
	for _, tx := range txs {
		if len(tx.Candidates) == 0 {
			continue
		}
		best, ok := pickBestCandidate(tx.Candidates, onlyTCP)
		if !ok {
			tx.Candidates = nil
			continue
		}

		p := best.Port
		tx.DestinationPort = &p
		tx.ProtocolL4 = best.Proto
		tx.Candidates = nil
	}

	type edgeKey struct {
		issuer string
		dst    string
		proto  connectivity.L4Proto
		port   uint16
	}

	// Flatten per-file edges in discovered file order and preserve the first
	// occurrence of each endpoint tuple.
	seenEdges := make(map[edgeKey]struct{}, 65536)
	var out []connectivity.Edge
	for _, batch := range edgeBatches {
		for _, e := range batch {
			k := edgeKey{
				issuer: e.IssuerIP,
				dst:    e.DstIP,
				proto:  e.Protocol,
				port:   e.Port,
			}
			if _, ok := seenEdges[k]; ok {
				continue
			}
			seenEdges[k] = struct{}{}
			out = append(out, e)
		}
	}
	return out, firstPkt, nil
}

func AttachConnectionsFromPCAPs(ctx context.Context, files []string, txs []*DNSTransaction, onlyTCP bool) error {
	_, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(ctx, files, txs, onlyTCP, nil, false)
	return err
}

// pickBestCandidate selects the best connection candidate for a DNS transaction.
//
// When onlyTCP is true, only TCP candidates carrying a TCP protocol tag are
// considered. Among the remaining candidates, the one with the smallest time
// delta (closest in time to the DNS request) is preferred.
func pickBestCandidate(cands []ConnCandidate, onlyTCP bool) (ConnCandidate, bool) {
	var best ConnCandidate
	var hasBest bool

	for _, cand := range cands {
		if onlyTCP && cand.Proto != L4ProtoTCP {
			continue
		}
		if !hasBest || cand.DT < best.DT {
			best = cand
			hasBest = true
		}
	}

	return best, hasBest
}

// scanDNSInFile reads a single PCAP/PCAPNG file and extracts DNS A query/response
// transactions into a per-file TxKey->[]*DNSTransaction map.
//
// Key properties:
//   - Uses pcapgo for BOTH pcap and pcapng (avoids libpcap/cgo stalls under Delve).
//   - Cancellable receive loop: ctx cancellation works even if packet decoding stalls.
//   - In-code filtering (instead of BPF): only processes packets that actually contain DNS.
func scanDNSInFile(ctx context.Context, path string) (map[TxKey][]*DNSTransaction, time.Time, error) {
	txMap := make(map[TxKey][]*DNSTransaction)
	byLookup := make(map[txLookupKey][]*DNSTransaction)

	var earliest time.Time
	first := true

	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer f.Close()

	// Detect pcapng magic: 0A 0D 0D 0A
	r := bufio.NewReader(f)
	magic, _ := r.Peek(4)

	var (
		src *gopacket.PacketSource
	)

	if len(magic) == 4 && magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		// pcapng
		ngr, e := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if e != nil {
			return nil, time.Time{}, fmt.Errorf("pcapng reader %s: %w", path, e)
		}
		src = gopacket.NewPacketSource(ngr, ngr.LinkType())
	} else {
		// classic pcap
		pr, e := pcapgo.NewReader(r)
		if e != nil {
			return nil, time.Time{}, fmt.Errorf("pcap reader %s: %w", path, e)
		}
		src = gopacket.NewPacketSource(pr, pr.LinkType())
	}

	// Avoid extra allocations where possible.
	src.NoCopy = true

	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()

		case packet, ok := <-packets:
			if !ok {
				// EOF or PacketSource stopped and closed channel.
				return txMap, earliest, nil
			}

			md := packet.Metadata()
			if md == nil {
				continue
			}

			ts := md.Timestamp
			if first || ts.Before(earliest) {
				earliest = ts
				first = false
			}

			// DNS layer check first (cheap short-circuit for most packets).
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer == nil {
				continue
			}
			d, _ := dnsLayer.(*layers.DNS)
			if d == nil {
				continue
			}

			// We only care about UDP/TCP port 53 DNS.
			// (pcapgo can't do BPF, so do minimal filtering here.)
			var (
				proto   L4Proto
				srcPort uint16
				dstPort uint16
				payload []byte
			)
			if udpL := packet.Layer(layers.LayerTypeUDP); udpL != nil {
				udp := udpL.(*layers.UDP)
				proto = L4ProtoUDP
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
				payload = udp.Payload
			} else if tcpL := packet.Layer(layers.LayerTypeTCP); tcpL != nil {
				tcp := tcpL.(*layers.TCP)
				proto = L4ProtoTCP
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
				payload = tcp.Payload
			} else {
				continue
			}
			if srcPort != 53 && dstPort != 53 {
				continue
			}

			// IPs (v4 or v6)
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ip4Layer == nil && ip6Layer == nil {
				continue
			}

			var srcIP, dstIP net.IP
			if ip4Layer != nil {
				ip4 := ip4Layer.(*layers.IPv4)
				srcIP, dstIP = ip4.SrcIP, ip4.DstIP
			} else {
				ip6 := ip6Layer.(*layers.IPv6)
				srcIP, dstIP = ip6.SrcIP, ip6.DstIP
			}
			if srcIP == nil || dstIP == nil {
				continue
			}

			captureTruncated := md.Truncated || (md.CaptureInfo.Length > 0 && md.CaptureInfo.CaptureLength < md.CaptureInfo.Length)

			// --- Queries ---
			if !d.QR && len(d.Questions) > 0 {
				q := d.Questions[0]
				if q.Type != layers.DNSTypeA {
					continue
				}

				dnsName := canonicalDNSName(string(q.Name))
				if dnsName == "" {
					continue
				}

				key := TxKey{
					Issuer:   srcIP.String(),
					SrcPort:  srcPort,
					Resolver: dstIP.String(),
					Proto:    proto,
					ID:       d.ID,
					Name:     dnsName,
				}

				tx := &DNSTransaction{
					RequestTime:  ts.UTC(),
					IssuerIP:     append(net.IP(nil), srcIP...),
					DNSName:      dnsName,
					ResolverIP:   append(net.IP(nil), dstIP...),
					NameEvidence: EvDNSAnswer, // NEW
					PCAPFile:     filepath.Base(path),
				}
				txMap[key] = append(txMap[key], tx)
				lk := makeTxLookupKey(key.Issuer, key.SrcPort, key.Resolver, key.Proto, key.ID)
				byLookup[lk] = append(byLookup[lk], tx)
				continue
			}

			// --- Responses ---
			if d.QR {
				var (
					answers  []net.IP
					respName string
					respID   uint16
				)

				respID = d.ID
				if len(d.Questions) > 0 {
					respName = canonicalDNSName(string(d.Questions[0].Name))
				}

				for _, ans := range d.Answers {
					if ans.Type == layers.DNSTypeA && len(ans.IP) > 0 {
						answers = append(answers, append(net.IP(nil), ans.IP...))
					}
				}

				if captureTruncated && srcPort == 53 {
					rawID, rawName, rawAnswers, ok := extractDNSResponseFromRaw(payload, proto, true)
					if ok {
						if respID == 0 {
							respID = rawID
						}
						if respName == "" {
							respName = rawName
						}
						answers = append(answers, rawAnswers...)
					}
				}

				if respID == 0 || len(answers) == 0 {
					continue
				}

				lk := makeTxLookupKey(
					dstIP.String(), // original query src
					dstPort,        // original query src port
					srcIP.String(), // original query dst
					proto,
					respID,
				)
				cands := byLookup[lk]
				if len(cands) == 0 {
					continue
				}

				tx := pickResponseTx(cands, respName, ts.UTC())
				if tx == nil {
					continue
				}

				tx.NameEvidence = EvDNSAnswer
				for _, ip := range answers {
					tx.AddResolvedIP(ip, EvDNSAnswer)
				}
				if len(tx.ResolvedIPs) > 0 {
					tx.ResolverIP = append(net.IP(nil), srcIP...)
				}
			}
		}
	}
}
