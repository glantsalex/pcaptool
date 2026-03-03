// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import "strings"

// Evidence is a bitmask describing how a DNSName<->IP association was obtained.
type Evidence uint16

const (
	EvNone Evidence = 0

	// Primary sources
	EvDNSAnswer     Evidence = 1 << 0 // parsed from DNS response in PCAP
	EvSNI           Evidence = 1 << 1 // derived from TLS SNI synthetic transaction
	EvActiveResolve Evidence = 1 << 2 // resolved via active DNS lookup (pass 2.5)
	EvCSV           Evidence = 1 << 3 // resolved via user-provided CSV mapping
	EvConnInferred  Evidence = 1 << 4 // inferred from connectivity when DNS answers missing

	// Validation / confirmation
	EvObservedConn Evidence = 1 << 5 // confirmed by SYN-ACK (TCP) or reply (UDP)
)

// EvidenceString returns a stable, compact label for output columns.
// Examples: "dns+synack", "active+synack", "csv+synack", "conn+synack", "sni+synack".
func EvidenceString(ev Evidence) string {
	if ev == EvNone {
		return ""
	}
	var parts []string

	// Prefer primary-source tokens first
	if ev&EvDNSAnswer != 0 {
		parts = append(parts, "dns")
	}
	if ev&EvSNI != 0 {
		parts = append(parts, "sni")
	}
	if ev&EvActiveResolve != 0 {
		parts = append(parts, "active")
	}
	if ev&EvCSV != 0 {
		parts = append(parts, "csv")
	}
	if ev&EvConnInferred != 0 {
		parts = append(parts, "conn")
	}

	// Then confirmation token (your “SYN-ACK observed” semantics)
	if ev&EvObservedConn != 0 {
		parts = append(parts, "synack")
	}

	return strings.Join(parts, "+")
}
