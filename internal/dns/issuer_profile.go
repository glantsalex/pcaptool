// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"sort"
)

type IssuerProfile struct {
	IssuerIP       string
	TotalDNS       int
	UniqueNames    int
	UniqueIPs      int
	UniquePorts    int
	ConnectionRate float64
}

func ComputeIssuerProfile(txs []*DNSTransaction) []IssuerProfile {
	type agg struct {
		totalDNS  int
		names     map[string]struct{}
		ips       map[string]struct{}
		ports     map[uint16]struct{}
		connected int
	}

	m := make(map[string]*agg)

	for _, tx := range txs {
		issuer := tx.IssuerLabel
		if issuer == "" && tx.IssuerIP != nil {
			issuer = tx.IssuerIP.String()
		}
		if issuer == "" {
			continue
		}
		a, ok := m[issuer]
		if !ok {
			a = &agg{
				names: make(map[string]struct{}),
				ips:   make(map[string]struct{}),
				ports: make(map[uint16]struct{}),
			}
			m[issuer] = a
		}

		a.totalDNS++
		a.names[tx.DNSName] = struct{}{}

		// Resolved IPs
		for _, ip := range tx.ResolvedIPs {
			a.ips[ip.String()] = struct{}{}
		}

		// Connected? DestinationPort may be nil when no connection matched.
		if tx.DestinationPort != nil && *tx.DestinationPort > 0 {
			a.connected++
			a.ports[*tx.DestinationPort] = struct{}{}
		}
	}

	res := make([]IssuerProfile, 0, len(m))

	for issuer, a := range m {
		rate := 0.0
		if a.totalDNS > 0 {
			rate = float64(a.connected) / float64(a.totalDNS)
		}

		res = append(res, IssuerProfile{
			IssuerIP:       issuer,
			TotalDNS:       a.totalDNS,
			UniqueNames:    len(a.names),
			UniqueIPs:      len(a.ips),
			UniquePorts:    len(a.ports),
			ConnectionRate: rate,
		})
	}

	// Sort by total DNS desc, then issuer IP asc.
	sort.Slice(res, func(i, j int) bool {
		if res[i].TotalDNS != res[j].TotalDNS {
			return res[i].TotalDNS > res[j].TotalDNS
		}
		return res[i].IssuerIP < res[j].IssuerIP
	})

	return res
}
