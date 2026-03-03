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
)

// ConnectivityEntry represents a single unique edge:
// IssuerIP -> DNSName -> ResolvedIP -> DestinationPort.
type ConnectivityEntry struct {
	IssuerIP   string
	DNSName    string
	ResolvedIP string
	Port       uint16
}

// ComputeConnectivityMatrix returns a de-duplicated, sorted slice of
// issuer→DNS→IP→port entries, using only transactions that actually
// have a matched connection (DestinationPort != nil) and at least one
// resolved IP.
//
// The "issuer" column uses tx.IssuerLabel when set (e.g. IMSI in
// --radius-imsi mode) and falls back to the issuer IP string otherwise.
func ComputeConnectivityMatrix(txs []*DNSTransaction) []ConnectivityEntry {
	type key struct {
		issuer string
		name   string
		ip     string
		port   uint16
	}

	seen := make(map[key]struct{})
	out := make([]ConnectivityEntry, 0)

	for _, tx := range txs {
		// Only consider transactions that ended in a connection
		if tx.DestinationPort == nil || *tx.DestinationPort == 0 {
			continue
		}
		if len(tx.ResolvedIPs) == 0 {
			// No resolved IP to show; skip for connectivity matrix
			continue
		}

		issuer := tx.IssuerLabel
		if issuer == "" && tx.IssuerIP != nil {
			issuer = tx.IssuerIP.String()
		}
		if issuer == "" {
			continue
		}

		port := uint16(*tx.DestinationPort)

		for _, ip := range tx.ResolvedIPs {
			if ip == nil || ip.Equal(net.IP{}) {
				continue
			}
			ipStr := ip.String()

			k := key{
				issuer: issuer,
				name:   tx.DNSName,
				ip:     ipStr,
				port:   port,
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}

			out = append(out, ConnectivityEntry{
				IssuerIP:   issuer,
				DNSName:    tx.DNSName,
				ResolvedIP: ipStr,
				Port:       port,
			})
		}
	}

	if len(out) == 0 {
		return nil
	}

	// Sort by issuer, then DNS name, then IP, then port for a nice grouping.
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		if out[i].DNSName != out[j].DNSName {
			return out[i].DNSName < out[j].DNSName
		}
		if out[i].ResolvedIP != out[j].ResolvedIP {
			return out[i].ResolvedIP < out[j].ResolvedIP
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return false
	})

	return out
}

// SquashConnectivityShort collapses connectivity entries so that, for each issuer,
// DNS name, and port, only a single entry is kept. The ResolvedIP of the first
// encountered entry is kept, and additional IPs for the same (issuer, DNS, port)
// are ignored for brevity.
//
// This is used for "short" connectivity matrix output.
func SquashConnectivityShort(entries []ConnectivityEntry) []ConnectivityEntry {
	if len(entries) == 0 {
		return entries
	}

	type key struct {
		issuer string
		name   string
		port   uint16
	}

	m := make(map[key]ConnectivityEntry, len(entries))

	for _, e := range entries {
		k := key{
			issuer: e.IssuerIP,
			name:   e.DNSName,
			port:   e.Port,
		}
		if _, exists := m[k]; exists {
			// Already have a representative for this issuer/DNS/port; skip.
			continue
		}
		m[k] = e
	}

	out := make([]ConnectivityEntry, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}

	// Keep same sort order as full matrix: issuer, DNS, IP, port
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		if out[i].DNSName != out[j].DNSName {
			return out[i].DNSName < out[j].DNSName
		}
		if out[i].ResolvedIP != out[j].ResolvedIP {
			return out[i].ResolvedIP < out[j].ResolvedIP
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return false
	})

	return out
}
