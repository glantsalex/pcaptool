// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
)

// ServiceEndpoint is one unique public endpoint tuple for external ingestion.
//
// Uniqueness key: (ip, dns, port)
type ServiceEndpoint struct {
	IP         string `json:"ip"`
	DNS        string `json:"dns"`
	Port       uint16 `json:"port"`
	HashVal    int64  `json:"hash_val"`
	ObservedAt int64  `json:"observed_at"` // unix milliseconds
}

// BuildServiceEndpoints builds a unique, deterministic list of service endpoints
// from topology rows.
//
// Rules:
//   - include only public destination IPv4 with non-empty DNS and non-zero port
//   - dedupe by (ip,dns,port), issuer ignored
//   - observed_at is earliest timestamp among duplicates (unix ms)
func BuildServiceEndpoints(entries []TopologyEntry) []ServiceEndpoint {
	type key struct {
		ip   string
		dns  string
		port uint16
	}

	best := make(map[key]ServiceEndpoint, len(entries))

	for _, e := range entries {
		if e.Port == 0 {
			continue
		}
		ip, ok := canonicalIPv4String(e.DestinationIP)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !isPublicIPv4(addr) {
			continue
		}
		dnsName := canonicalDNSName(e.DNSName)
		if dnsName == "" {
			continue
		}

		k := key{ip: ip, dns: dnsName, port: e.Port}
		obs := int64(0)
		if !e.ObservedAt.IsZero() {
			obs = e.ObservedAt.UTC().UnixMilli()
		}

		cur, exists := best[k]
		if !exists {
			best[k] = ServiceEndpoint{
				IP:         ip,
				DNS:        dnsName,
				Port:       e.Port,
				HashVal:    serviceEndpointHash64(ip, dnsName, e.Port),
				ObservedAt: obs,
			}
			continue
		}
		if cur.ObservedAt == 0 || (obs > 0 && obs < cur.ObservedAt) {
			cur.ObservedAt = obs
			best[k] = cur
		}
	}

	out := make([]ServiceEndpoint, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if out[i].DNS != out[j].DNS {
			return out[i].DNS < out[j].DNS
		}
		return out[i].Port < out[j].Port
	})

	return out
}

func serviceEndpointHash64(ip, dns string, port uint16) int64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", ip, dns, port)
	return int64(h.Sum64())
}
