// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"sort"
	"strings"
)

const maxUnusedPCAPFiles = 3

type DNSUnusedStat struct {
	Name        string
	Issuers     []string
	ResolvedIPs []string
	PCAPFiles   []string
}

type TableStats struct {
	UniqueSources      int
	UniqueDestIPs      int
	UniqueConnectedDNS int
	Unused             []DNSUnusedStat
}

type DNSUnresolvedStat struct {
	Name          string
	IssuerIP      string
	FirstPCAPFile string
}

// ComputeTableStats takes:
//
//   - allRecords: all DNS transactions (with and without connections)
//   - usedRecords: only the filtered records that have real connections
//
// and returns stats for table footer.
func ComputeTableStats(allRecords, usedRecords []OutputRecord) TableStats {
	sourceSet := make(map[string]struct{})
	destIPSet := make(map[string]struct{})
	connectedDNSSet := make(map[string]struct{})

	// track which DNS names EVER had a connection
	namesWithConn := make(map[string]struct{})

	// From usedRecords: sources, dest IPs, DNS with connections
	for _, r := range usedRecords {
		sourceSet[r.IssuerIP] = struct{}{}

		for _, ip := range r.ResolvedIPs {
			destIPSet[ip] = struct{}{}
		}

		connectedDNSSet[r.DNSName] = struct{}{}
		namesWithConn[r.DNSName] = struct{}{}
	}

	// For unused: names that appear in allRecords but NEVER in usedRecords
	// and collect their pcap files.
	unusedFiles := make(map[string]map[string]struct{}) // name -> set of pcap files

	for _, r := range allRecords {
		if r.DNSName == "" {
			continue
		}
		if _, ok := namesWithConn[r.DNSName]; ok {
			// this DNS name has at least one connected instance
			continue
		}
		if r.PCAPFile == "" {
			continue
		}

		fs, ok := unusedFiles[r.DNSName]
		if !ok {
			fs = make(map[string]struct{})
			unusedFiles[r.DNSName] = fs
		}
		fs[r.PCAPFile] = struct{}{}
	}

	unused := make([]DNSUnusedStat, 0, len(unusedFiles))
	for name, set := range unusedFiles {
		files := make([]string, 0, len(set))
		for f := range set {
			files = append(files, f)
		}
		sort.Strings(files)

		if len(files) > maxUnusedPCAPFiles {
			files = files[:maxUnusedPCAPFiles]
		}

		unused = append(unused, DNSUnusedStat{
			Name:      name,
			PCAPFiles: files,
		})
	}
	sort.Slice(unused, func(i, j int) bool {
		return unused[i].Name < unused[j].Name
	})

	return TableStats{
		UniqueSources:      len(sourceSet),
		UniqueDestIPs:      len(destIPSet),
		UniqueConnectedDNS: len(connectedDNSSet),
		Unused:             unused,
	}
}

func ComputeTableStatsFromTx(txs []*DNSTransaction, usedRecords []OutputRecord) TableStats {
	sourceSet := make(map[string]struct{})
	destIPSet := make(map[string]struct{})
	connectedDNSSet := make(map[string]struct{})

	// DNS names that ever had a connection (at tx level)
	namesWithConn := make(map[string]struct{})

	// 1) Unique sources/dests/connected DNS from usedRecords (printed rows)
	for _, r := range usedRecords {
		sourceSet[r.IssuerIP] = struct{}{}
		for _, ip := range r.ResolvedIPs {
			destIPSet[ip] = struct{}{}
		}
		if r.DNSName != "" {
			connectedDNSSet[r.DNSName] = struct{}{}
		}
	}

	// 2) At tx level, mark names that have a DestinationPort
	for _, tx := range txs {
		if tx.DNSName == "" {
			continue
		}
		if tx.DestinationPort != nil {
			namesWithConn[tx.DNSName] = struct{}{}
		}
	}

	// 3) For names that NEVER had a DestinationPort, collect issuers, resolved IPs, and PCAP files
	type agg struct {
		issuers     map[string]struct{}
		resolvedIPs map[string]struct{}
		pcaps       map[string]struct{}
	}
	unusedAgg := make(map[string]*agg) // name -> agg

	for _, tx := range txs {
		if tx.DNSName == "" {
			continue
		}
		if _, ok := namesWithConn[tx.DNSName]; ok {
			// this DNS name has at least one tx with a connection
			continue
		}
		if tx.PCAPFile == "" {
			continue
		}

		a, ok := unusedAgg[tx.DNSName]
		if !ok {
			a = &agg{
				issuers:     make(map[string]struct{}),
				resolvedIPs: make(map[string]struct{}),
				pcaps:       make(map[string]struct{}),
			}
			unusedAgg[tx.DNSName] = a
		}

		// issuer
		issuer := tx.IssuerIP.String()
		if issuer != "" {
			a.issuers[issuer] = struct{}{}
		}

		// resolved IPs from this tx
		for _, ip := range tx.ResolvedIPs {
			if ip == nil || len(ip) == 0 {
				continue
			}
			a.resolvedIPs[ip.String()] = struct{}{}
		}

		// pcap file
		a.pcaps[tx.PCAPFile] = struct{}{}
	}

	unused := make([]DNSUnusedStat, 0, len(unusedAgg))
	for name, a := range unusedAgg {
		issuers := make([]string, 0, len(a.issuers))
		for ip := range a.issuers {
			issuers = append(issuers, ip)
		}
		sort.Strings(issuers)

		resIPs := make([]string, 0, len(a.resolvedIPs))
		for ip := range a.resolvedIPs {
			resIPs = append(resIPs, ip)
		}
		sort.Strings(resIPs)

		files := make([]string, 0, len(a.pcaps))
		for f := range a.pcaps {
			files = append(files, f)
		}
		sort.Strings(files)

		unused = append(unused, DNSUnusedStat{
			Name:        name,
			Issuers:     issuers,
			ResolvedIPs: resIPs,
			PCAPFiles:   files,
		})
	}
	sort.Slice(unused, func(i, j int) bool {
		return unused[i].Name < unused[j].Name
	})

	return TableStats{
		UniqueSources:      len(sourceSet),
		UniqueDestIPs:      len(destIPSet),
		UniqueConnectedDNS: len(connectedDNSSet),
		Unused:             unused,
	}
}

// ComputeUnresolvedDNSFirstSeen returns unresolved DNS rows where decision is made
// by DNS name globally (issuer is context only):
//   - if a DNS name has at least one transaction with resolved IPs, it is treated
//     as resolved/used and excluded from this report for all issuers
//   - otherwise, we emit one row per issuer that queried that name
//   - FirstPCAPFile is the first observed file for that (name, issuer) context row
func ComputeUnresolvedDNSFirstSeen(txs []*DNSTransaction) []DNSUnresolvedStat {
	type rowKey struct {
		name   string
		issuer string
	}
	type rowAgg struct {
		firstPCAP string
	}

	nameHasResolved := make(map[string]bool)
	rows := make(map[rowKey]*rowAgg)

	for _, tx := range txs {
		if tx == nil {
			continue
		}
		name := canonicalDNSName(tx.DNSName)
		if name == "" {
			continue
		}
		if len(tx.ResolvedIPs) > 0 {
			nameHasResolved[name] = true
		}

		issuer := ""
		if tx.IssuerIP != nil {
			issuer = tx.IssuerIP.String()
		}
		k := rowKey{name: name, issuer: issuer}

		a, ok := rows[k]
		if !ok {
			a = &rowAgg{
				firstPCAP: tx.PCAPFile,
			}
			rows[k] = a
		}

		// Update firstPCAP if we somehow encounter an earlier file name
		// (not strictly necessary if txs are time-sorted and PCAPFile order is stable,
		// but harmless and more robust).
		if a.firstPCAP == "" {
			a.firstPCAP = tx.PCAPFile
		}
	}

	if len(rows) == 0 {
		return nil
	}

	// Build unresolved list: names that NEVER had any resolved IPs (issuer ignored).
	out := make([]DNSUnresolvedStat, 0, len(rows))
	for k, a := range rows {
		if nameHasResolved[k.name] {
			continue
		}
		out = append(out, DNSUnresolvedStat{
			Name:          k.name,
			IssuerIP:      k.issuer,
			FirstPCAPFile: a.firstPCAP,
		})
	}

	if len(out) == 0 {
		return nil
	}

	// Sort by DNS name for deterministic output.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		return out[i].FirstPCAPFile < out[j].FirstPCAPFile
	})

	return out
}

// FilterUnresolvedByTopologyAttribution drops unresolved DNS rows when the same
// DNS name is already attributed in topology output.
//
// This resolves apparent discrepancies such as:
// - dns-unresolved-dns.txt contains a name
// - network-topology-matrix.txt has the same name via csv+mid/csv+conn/dns+...
//
// Matching is case-insensitive and trailing-dot insensitive on DNS names.
func FilterUnresolvedByTopologyAttribution(unresolved []DNSUnresolvedStat, topo []TopologyEntry) []DNSUnresolvedStat {
	if len(unresolved) == 0 || len(topo) == 0 {
		return unresolved
	}

	normName := func(s string) string {
		return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	}

	resolvedNames := make(map[string]struct{}, len(topo))
	for _, row := range topo {
		if strings.TrimSpace(row.DNSName) == "" {
			continue
		}
		name := normName(row.DNSName)
		if name == "" {
			continue
		}
		resolvedNames[name] = struct{}{}
	}
	if len(resolvedNames) == 0 {
		return unresolved
	}

	out := make([]DNSUnresolvedStat, 0, len(unresolved))
	for _, u := range unresolved {
		name := normName(u.Name)
		if _, ok := resolvedNames[name]; ok {
			continue
		}
		out = append(out, u)
	}
	return out
}
