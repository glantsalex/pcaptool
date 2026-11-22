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

	pcaputil "github.com/aglants/pcaptool/internal/pcap"
	"github.com/aglants/pcaptool/progress"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// A hostnamePool belongs to the file-result coordinator for one extraction pass.
// Names arriving from DNS and SNI retain their existing spelling.
type hostnamePool map[string]string

func (p hostnamePool) share(name string) string {
	if name == "" {
		return ""
	}
	if stored, ok := p[name]; ok {
		return stored
	}
	p[name] = name
	return name
}

// BuildTransactionsWithSNIFromPCAPs performs a single corpus scan that always extracts:
//  1. DNS A query/response transactions (real DNS)
//
// and optionally extracts:
//  2. TLS ClientHello SNI synthetic transactions (SNI -> dstIP:port)
//
// It returns a single slice of *DNSTransaction containing DNS txs plus SNI txs
// when includeSNI is true. SNI synthetic txs already have DestinationPort set
// and are skipped by correlation index build.
func BuildTransactionsWithSNIFromPCAPs(ctx context.Context, files []string, includeSNI bool) ([]*DNSTransaction, time.Time, error) {
	txs, earliest, _, err := BuildTransactionsWithSNIFromPCAPsWithDiagnostics(ctx, files, includeSNI, false)
	return txs, earliest, err
}

// BuildTransactionsWithSNIFromPCAPsWithDiagnostics performs the normal DNS/SNI
// scan and optionally collects diagnostic-only truncated UDP DNS query records.
func BuildTransactionsWithSNIFromPCAPsWithDiagnostics(
	ctx context.Context,
	files []string,
	includeSNI bool,
	collectTruncatedDNS bool,
) ([]*DNSTransaction, time.Time, []TruncatedDNSPacket, error) {
	return BuildTransactionsWithSNIFromPCAPsWithOptions(
		ctx,
		files,
		includeSNI,
		collectTruncatedDNS,
		PacketScanOptions{},
	)
}

// BuildTransactionsWithSNIFromPCAPsWithOptions performs the DNS/SNI scan with
// optional packet admission applied before any extractor sees a packet.
func BuildTransactionsWithSNIFromPCAPsWithOptions(
	ctx context.Context,
	files []string,
	includeSNI bool,
	collectTruncatedDNS bool,
	opt PacketScanOptions,
) ([]*DNSTransaction, time.Time, []TruncatedDNSPacket, error) {
	type fileResult struct {
		txMap               map[TxKey][]*DNSTransaction
		sniTxs              []*DNSTransaction
		truncatedDNSPackets []TruncatedDNSPacket
		earliest            time.Time
		err                 error
		file                string
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
				txMap, sniTxs, truncatedDNSPackets, earliest, err := scanDNSAndSNIInFile(
					ctx,
					path,
					includeSNI,
					collectTruncatedDNS,
					opt.PacketAdmission,
				)
				resCh <- fileResult{
					txMap:               txMap,
					sniTxs:              sniTxs,
					truncatedDNSPackets: truncatedDNSPackets,
					earliest:            earliest,
					err:                 err,
					file:                path,
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
	names := make(hostnamePool, 10_000)
	globalMap := make(map[TxKey][]*DNSTransaction)
	var globalSNI []*DNSTransaction
	var truncatedDNSPackets []TruncatedDNSPacket

	// Global SNI dedup across files
	seenSNI := make(map[sniKey]int)

	var (
		globalEarliest time.Time
		firstEarliest  = true
		doneFiles      = 0
		totalFiles     = len(files)
	)

	for res := range resCh {
		if res.err != nil {
			return nil, time.Time{}, nil, res.err
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
			k.Name = names.share(k.Name)
			bucket := globalMap[k]
			for _, localTx := range localList {
				if localTx != nil {
					localTx.DNSName = names.share(localTx.DNSName)
				}
				bucket = mergeDNSTransactionIntoBucket(bucket, localTx)
			}
			sortTxBucketByTime(bucket)
			globalMap[k] = bucket
		}

		// Merge SNI synthetic txs with global dedup
		for _, tx := range res.sniTxs {
			if tx == nil || tx.IssuerIP == nil || tx.resolvedIPLen() == 0 || tx.DestinationPort == nil {
				continue
			}
			ip0 := tx.resolvedIPAt(0)
			if ip0.isNil() {
				continue
			}
			tx.DNSName = names.share(tx.DNSName)
			k := sniKey{
				observedAt: tx.RequestTime.UTC(),
				issuer:     tx.IssuerIP.String(),
				dstIP:      ip0.String(),
				port:       *tx.DestinationPort,
				sni:        tx.DNSName,
			}
			if idx, exists := seenSNI[k]; exists {
				// Duplicate capture copies choose stable provenance, independent
				// of worker completion order. Identity is resolved downstream.
				if tx.PCAPFile < globalSNI[idx].PCAPFile {
					globalSNI[idx] = tx
				}
				continue
			}
			seenSNI[k] = len(globalSNI)
			globalSNI = append(globalSNI, tx)
		}

		truncatedDNSPackets = append(truncatedDNSPackets, res.truncatedDNSPackets...)
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
			return transactionTieLess(txs[i], txs[j])
		}
		return ti.Before(tj)
	})
	sort.Slice(truncatedDNSPackets, func(i, j int) bool {
		a, b := truncatedDNSPackets[i], truncatedDNSPackets[j]
		if !a.TimestampUTC.Equal(b.TimestampUTC) {
			return a.TimestampUTC.Before(b.TimestampUTC)
		}
		if a.PCAPFile != b.PCAPFile {
			return a.PCAPFile < b.PCAPFile
		}
		if a.SrcIP != b.SrcIP {
			return a.SrcIP < b.SrcIP
		}
		if a.DstIP != b.DstIP {
			return a.DstIP < b.DstIP
		}
		if a.SrcPort != b.SrcPort {
			return a.SrcPort < b.SrcPort
		}
		if a.DstPort != b.DstPort {
			return a.DstPort < b.DstPort
		}
		if a.TxID != b.TxID {
			return a.TxID < b.TxID
		}
		if a.TruncatedDNSName != b.TruncatedDNSName {
			return a.TruncatedDNSName < b.TruncatedDNSName
		}
		return a.Reason < b.Reason
	})

	progress.UpdateBar(totalFiles, totalFiles, "DNS+SNI scan complete")
	return txs, globalEarliest, truncatedDNSPackets, nil
}

func scanDNSAndSNIInFile(
	ctx context.Context,
	path string,
	includeSNI bool,
	collectTruncatedDNS bool,
	admit pcaputil.PacketAdmission,
) (map[TxKey][]*DNSTransaction, []*DNSTransaction, []TruncatedDNSPacket, time.Time, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer handle.Close()

	// Decode link encapsulation before selecting transports. A plain libpcap
	// "udp port 53 or tcp" filter silently drops VLAN-tagged DNS and TLS.

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	dnsEx := newDNSExtractorWithDiagnostics(collectTruncatedDNS)
	var sniEx *sniExtractor
	if includeSNI {
		sniEx = newSNIExtractor()
	}

	packets := src.Packets()
	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, time.Time{}, ctx.Err()

		case pkt, ok := <-packets:
			if !ok {
				// EOF
				earliest := dnsEx.Earliest()
				if sniEx != nil {
					if s := sniEx.Earliest(); !s.IsZero() && (earliest.IsZero() || s.Before(earliest)) {
						earliest = s
					}
				}
				var sniTxs []*DNSTransaction
				if sniEx != nil {
					sniTxs = sniEx.Slice()
				}
				return dnsEx.Map(), sniTxs, dnsEx.TruncatedDNSPackets(), earliest, nil
			}
			if !isDNSOrSNIPacket(pkt, includeSNI) || (admit != nil && !admit(pkt)) {
				continue
			}

			base := filepath.Base(path)

			// Feed both extractors (each will early-return quickly if irrelevant)
			dnsEx.OnPacket(pkt, base)
			if sniEx != nil {
				sniEx.OnPacket(pkt, base)
			}
		}
	}
}

// isDNSOrSNIPacket preserves the scan's UDP/53 plus optional TCP selection
// after VLAN/QinQ decoding. Check the outer IP protocol so quoted packets in
// ICMP errors cannot become independent DNS/SNI evidence.
func isDNSOrSNIPacket(pkt gopacket.Packet, includeSNI bool) bool {
	var protocol layers.IPProtocol
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		protocol = ip.Protocol
	case *layers.IPv6:
		protocol = ip.NextHeader
	default:
		return false
	}
	if protocol == layers.IPProtocolTCP {
		return includeSNI
	}
	if protocol != layers.IPProtocolUDP {
		return false
	}
	udp, ok := pkt.TransportLayer().(*layers.UDP)
	return ok && (udp.SrcPort == 53 || udp.DstPort == 53)
}
