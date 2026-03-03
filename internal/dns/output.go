// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net"
	"sort"
	"strconv"
)

// OutputRecord is the flattened view used by table / JSON / CSV output.
//
// Notes:
//   - RequestTimeStr is UTC, "2006-01-02 15:04:05.000"
//   - ResolvedIPs are deduplicated per DNS transaction
//   - DestinationPort is nil when there was no matched connection
//   - PCAPFile is table-only (json:"-" hides it in JSON)
type OutputRecord struct {
	RequestTimeStr string   `json:"request_time"`
	IssuerIP       string   `json:"issuer_ip"`
	DNSName        string   `json:"dns_name"`
	ResolvedIPs    []string `json:"resolved_ips"`

	// ResolvedIPSources maps resolved IPv4 string -> source evidence label, e.g.:
	// "dns+synack", "active+synack", "csv+synack", "sni+synack", "conn+synack".
	// Keys correspond to values in ResolvedIPs (IPv4 only in our pipeline).
	ResolvedIPSources map[string]string `json:"resolved_ip_sources,omitempty"`

	ResolverIP      *string `json:"resolver_ip,omitempty"`
	DestinationPort *int    `json:"destination_port"`
	PCAPFile        string  `json:"-"` // used only by table renderer
}

// FilterAndDedupRecords:
//   - drop records with no destination_port
//   - keep only one record per (issuer_ip, dns_name, destination_port)
//     (earliest one wins because we sort by time later)
func FilterAndDedupRecords(records []OutputRecord) []OutputRecord {
	out := make([]OutputRecord, 0, len(records))
	seen := make(map[string]struct{}, len(records))

	for _, r := range records {
		if r.DestinationPort == nil {
			// no real connection to resolved IP -> skip
			continue
		}

		key := r.IssuerIP + "|" + r.DNSName + "|" + strconv.Itoa(*r.DestinationPort)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}

	return out
}

// ToOutputRecords converts DNSTransaction objects into OutputRecords.
// It also deduplicates ResolvedIPs per transaction.
func ToOutputRecords(txs []*DNSTransaction) []OutputRecord {
	records := make([]OutputRecord, 0, len(txs))

	for _, tx := range txs {
		issuer := tx.IssuerLabel
		if issuer == "" && tx.IssuerIP != nil {
			issuer = tx.IssuerIP.String()
		}

		rec := OutputRecord{
			RequestTimeStr: tx.RequestTime.UTC().Format("2006-01-02 15:04:05.000"),
			IssuerIP:       issuer,
			DNSName:        tx.DNSName,
			PCAPFile:       tx.PCAPFile,
		}

		// --- Dedup resolved IPs while preserving order ---
		seen := make(map[string]struct{}, len(tx.ResolvedIPs))

		// We'll fill sources only when we have at least one non-empty label.
		var srcMap map[string]string

		for _, ip := range tx.ResolvedIPs {
			if ip == nil || ip.Equal(net.IP{}) {
				continue
			}

			// Force IPv4-only here (consistent with your rules).
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			s := ip4.String()

			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			rec.ResolvedIPs = append(rec.ResolvedIPs, s)

			// Evidence label for this IP (best-effort).
			ev := EvNone
			if tx.ResolvedIPEvidence != nil {
				ev = tx.ResolvedIPEvidence[s]
			}
			// Fallback: if map missing, fall back to NameEvidence (dns/sni)
			if ev == EvNone {
				ev = tx.NameEvidence
			}
			label := EvidenceString(ev)
			if label != "" {
				if srcMap == nil {
					srcMap = make(map[string]string, 4)
				}
				srcMap[s] = label
			}
		}

		if srcMap != nil {
			rec.ResolvedIPSources = srcMap
		}

		// Resolver IP (optional)
		if tx.ResolverIP != nil && !tx.ResolverIP.Equal(net.IP{}) {
			s := tx.ResolverIP.String()
			rec.ResolverIP = &s
		}

		// Destination port (optional)
		if tx.DestinationPort != nil {
			p := int(*tx.DestinationPort)
			rec.DestinationPort = &p
		}

		records = append(records, rec)
	}

	return records
}

// SortOutputRecords sorts by request time, then issuer ip.
func SortOutputRecords(records []OutputRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].RequestTimeStr == records[j].RequestTimeStr {
			return records[i].IssuerIP < records[j].IssuerIP
		}
		return records[i].RequestTimeStr < records[j].RequestTimeStr
	})
}
