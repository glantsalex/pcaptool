// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/aglants/pcaptool/progress"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// BuildTransactionsWithSNIFromPCAPs performs a single corpus scan that extracts:
//  1. DNS A query/response transactions (real DNS)
//  2. TLS ClientHello SNI synthetic transactions (SNI → dstIP:port)
//
// It returns a single slice of *DNSTransaction containing both sources.
// The SNI synthetic tx already have DestinationPort set and will be skipped
// by correlation index build (your BuildTxnIndex already does that).
func BuildTransactionsWithSNIFromPCAPs(ctx context.Context, files []string) ([]*DNSTransaction, time.Time, error) {
	type fileResult struct {
		txMap    map[TxKey][]*DNSTransaction
		sniTxs   []*DNSTransaction
		earliest time.Time
		err      error
		file     string
	}

	fileCh := make(chan string)
	resCh := make(chan fileResult)

	workers := max(min(max(runtime.GOMAXPROCS(0), 1), len(files)), 1)

	var wg sync.WaitGroup
	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()
			for path := range fileCh {
				txMap, sniTxs, earliest, err := scanDNSAndSNIInFile(ctx, path)
				resCh <- fileResult{
					txMap:    txMap,
					sniTxs:   sniTxs,
					earliest: earliest,
					err:      err,
					file:     path,
				}
			}
		}()
	}

	go func() {
		for _, path := range files {
			fileCh <- path
		}
		close(fileCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	// Global merge state (single goroutine consumer => no locks needed)
	globalMap := make(map[TxKey][]*DNSTransaction)
	var globalSNI []*DNSTransaction

	// Global SNI dedup across files
	type sniDedupKey struct {
		issuer string
		dstIP  string
		port   uint16
		sni    string
	}
	seenSNI := make(map[sniDedupKey]struct{})

	var (
		globalEarliest time.Time
		firstEarliest  = true
		doneFiles      = 0
		totalFiles     = len(files)
	)

	for res := range resCh {
		if res.err != nil {
			return nil, time.Time{}, res.err
		}

		doneFiles++
		progress.UpdateBar(doneFiles, totalFiles, "DNS+SNI "+filepath.Base(res.file))

		if !res.earliest.IsZero() && (firstEarliest || res.earliest.Before(globalEarliest)) {
			globalEarliest = res.earliest
			firstEarliest = false
		}

		// Merge DNS maps by TxKey while preserving distinct per-key query instances.
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

		// Merge SNI synthetic txs with global dedup
		for _, tx := range res.sniTxs {
			if tx == nil || tx.IssuerIP == nil || len(tx.ResolvedIPs) == 0 || tx.DestinationPort == nil {
				continue
			}
			ip0 := tx.ResolvedIPs[0]
			if ip0 == nil {
				continue
			}
			k := sniDedupKey{
				issuer: tx.IssuerIP.String(),
				dstIP:  ip0.String(),
				port:   *tx.DestinationPort,
				sni:    tx.DNSName,
			}
			if _, exists := seenSNI[k]; exists {
				continue
			}
			seenSNI[k] = struct{}{}
			globalSNI = append(globalSNI, tx)
		}
	}

	// Convert globalMap to slice
	var txs []*DNSTransaction
	for _, bucket := range globalMap {
		txs = append(txs, bucket...)
	}

	// Append SNI txs
	if len(globalSNI) > 0 {
		txs = append(txs, globalSNI...)
	}

	// Sort by RequestTime for deterministic downstream behavior
	sort.Slice(txs, func(i, j int) bool {
		ti := txs[i].RequestTime
		tj := txs[j].RequestTime
		if ti.Equal(tj) {
			return txs[i].DNSName < txs[j].DNSName
		}
		return ti.Before(tj)
	})

	progress.UpdateBar(totalFiles, totalFiles, "DNS+SNI scan complete")
	return txs, globalEarliest, nil
}

func scanDNSAndSNIInFile(ctx context.Context, path string) (map[TxKey][]*DNSTransaction, []*DNSTransaction, time.Time, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer handle.Close()

	// Performance: keep DNS cheap and SNI feasible.
	// This filters out non-DNS UDP entirely, but includes all TCP for ClientHello parsing.
	if err := handle.SetBPFFilter("udp port 53 or tcp"); err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("set BPF filter on %s: %w", path, err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	dnsEx := newDNSExtractor()
	sniEx := newSNIExtractor()

	packets := src.Packets()
	for {
		select {
		case <-ctx.Done():
			return nil, nil, time.Time{}, ctx.Err()

		case pkt, ok := <-packets:
			if !ok {
				// EOF
				earliest := dnsEx.Earliest()
				if s := sniEx.Earliest(); !s.IsZero() && (earliest.IsZero() || s.Before(earliest)) {
					earliest = s
				}
				return dnsEx.Map(), sniEx.Slice(), earliest, nil
			}

			base := filepath.Base(path)

			// Feed both extractors (each will early-return quickly if irrelevant)
			dnsEx.OnPacket(pkt, base)
			sniEx.OnPacket(pkt, base)
		}
	}
}
