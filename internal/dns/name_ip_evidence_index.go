// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import "strings"

// nameIPKey builds a stable key for (dnsName, ip).
func nameIPKey(name, ip string) string {
	n := strings.TrimSpace(strings.TrimSuffix(name, "."))
	n = strings.ToLower(n)
	return n + "\x00" + ip
}

// normalizeEvidence prevents weak inference tokens from “escalating” output
// when stronger provenance exists for the same (dnsName, ip) pair.
//
// Rule: if we have any strong primary source (dns/sni/active/csv) we drop
// EvConnInferred. EvObservedConn is a confirmation flag and is preserved.
func normalizeEvidence(ev Evidence) Evidence {
	if ev == EvNone {
		return ev
	}
	strong := ev & (EvDNSAnswer | EvSNI | EvActiveResolve | EvCSV)
	if strong != 0 {
		ev &^= EvConnInferred
	}
	return ev
}

// BuildNameIPEvidenceIndex returns a map keyed by (dnsName, ipStr) -> Evidence.
// We OR evidence across all transactions that mention this name/ip.
//
// Important: we normalize evidence per (name,ip) so that connection-inference
// cannot override a stronger primary source for the same pair.
func BuildNameIPEvidenceIndex(hostnames *Hostnames, txs []*DNSTransaction) map[string]Evidence {
	idx := make(map[string]Evidence, 4096)

	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.DNSNameID == 0 {
			continue
		}

		// Iterate resolved IPv4s only.
		for i := 0; i < tx.resolvedIPLen(); i++ {
			ip := tx.resolvedIPAt(i)
			if ip.isNil() {
				continue
			}
			ip4 := ip.To4()
			if ip4.isNil() {
				continue
			}
			ipStr := ip4.String()

			ev := EvNone
			if tx.hasResolvedIPEvidence() {
				ev = tx.resolvedIPEvidenceValue(ipStr)
			}

			// OR name-level evidence as a safety net.
			// (Older transactions may not populate ResolvedIPEvidence.)
			ev |= tx.NameEvidence

			k := nameIPKey(hostnames.name(tx.DNSNameID), ipStr)
			idx[k] = normalizeEvidence(idx[k] | ev)
		}
	}

	return idx
}

// NameIPSourceLabel returns the final printable label for a (dnsName, ip) pair.
// If forceObservedConn is true, EvObservedConn is OR’d in (topology edges imply that anyway).
func NameIPSourceLabel(idx map[string]Evidence, dnsName, ip string, forceObservedConn bool) string {
	if dnsName == "" || ip == "" || idx == nil {
		return ""
	}

	ev := idx[nameIPKey(dnsName, ip)]
	if ev == EvNone {
		return ""
	}

	if forceObservedConn {
		ev |= EvObservedConn
	}

	ev = normalizeEvidence(ev)
	return EvidenceString(ev)
}
