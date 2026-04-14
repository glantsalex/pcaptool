// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// UnresolvedIPEndpoint describes one unresolved destination endpoint observed in the current run.
type UnresolvedIPEndpoint struct {
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	Count int    `json:"count"`
}

// PublicUnresolvedDestinationEndpoints returns unresolved public destination endpoints
// grouped by (ip, port, protocol), with occurrence counts.
//
// Input is expected to be the final topology entries (post-join).
func PublicUnresolvedDestinationEndpoints(entries []TopologyEntry) []UnresolvedIPEndpoint {
	type key struct {
		ip    string
		port  uint16
		proto string
	}
	counts := make(map[key]int, 1024)

	for _, e := range entries {
		if strings.TrimSpace(e.DNSName) != "" {
			continue // has DNS name
		}
		ipStr := strings.TrimSpace(e.DestinationIP)
		if ipStr == "" {
			continue
		}

		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			continue
		}
		if !isPublicIPv4(addr) {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(e.Protocol))
		if proto == "" {
			continue
		}
		counts[key{ip: ipStr, port: e.Port, proto: proto}]++
	}

	if len(counts) == 0 {
		return nil
	}

	out := make([]UnresolvedIPEndpoint, 0, len(counts))
	for k, count := range counts {
		out = append(out, UnresolvedIPEndpoint{
			IP:    k.ip,
			Port:  k.port,
			Proto: k.proto,
			Count: count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func WriteUnresolvedIPEndpointsJSON(w io.Writer, entries []UnresolvedIPEndpoint) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func isPublicIPv4(a netip.Addr) bool {
	// Basic non-public classes
	if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}

	// RFC1918 private
	if a.IsPrivate() {
		return false
	}

	// CGNAT 100.64.0.0/10 treated as non-public for topology purposes
	if netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return false
	}

	// Benchmarking / docs / reserved ranges (common “not really public”)
	if netip.MustParsePrefix("192.0.2.0/24").Contains(a) { // TEST-NET-1
		return false
	}
	if netip.MustParsePrefix("198.51.100.0/24").Contains(a) { // TEST-NET-2
		return false
	}
	if netip.MustParsePrefix("203.0.113.0/24").Contains(a) { // TEST-NET-3
		return false
	}

	// 0.0.0.0/8, 127.0.0.0/8 already covered by unspecified/loopback, but keep explicit
	if netip.MustParsePrefix("0.0.0.0/8").Contains(a) {
		return false
	}
	if netip.MustParsePrefix("127.0.0.0/8").Contains(a) {
		return false
	}

	return true
}
