// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net/netip"
	"sort"
	"strings"
)

// PublicUnresolvedDestinationIPs returns a sorted list of unique destination IPv4 addresses
// that have no DNS name attribution (DNSName == "").
//
// Input is expected to be the final topology entries (post-join).
func PublicUnresolvedDestinationIPs(entries []TopologyEntry) []string {
	set := make(map[string]struct{}, 1024)

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
		set[ipStr] = struct{}{}
	}

	if len(set) == 0 {
		return nil
	}

	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
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
