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
	"strings"
)

const (
	serviceEndpointNoDNSAttribution = "[no-dns-attribution]"
	serviceEndpointPrivateServer    = "[private-server]"
)

// ServiceEndpoint is one unique endpoint tuple for external ingestion.
//
// Uniqueness key: (ip, dns, protocol, port)
type ServiceEndpoint struct {
	IP         string `json:"ip"`
	DNS        string `json:"dns"`
	Protocol   string `json:"protocol"`
	Port       uint16 `json:"port"`
	PeersCount int    `json:"peers_count"`
	HashVal    int64  `json:"hash_val"`
	ObservedAt int64  `json:"observed_at"` // unix milliseconds
}

// BuildServiceEndpoints builds a unique, deterministic list of service endpoints
// from topology rows.
//
// Rules:
//   - include destination IPv4 with non-zero port
//   - dedupe by (ip,dns,protocol,port)
//   - observed_at is earliest timestamp among duplicates (unix ms)
//   - peers_count is number of unique non-public IPv4 issuers that talked to that endpoint
//   - when no real DNS exists for an (ip,protocol,port) tuple:
//   - public IPs use [no-dns-attribution]
//   - non-public IPs use [private-server]
func BuildServiceEndpoints(entries []TopologyEntry) []ServiceEndpoint {
	type tupleKey struct {
		ip    string
		proto string
		port  uint16
	}
	type dnsKey struct {
		ip    string
		dns   string
		proto string
		port  uint16
	}
	type agg struct {
		endpoint ServiceEndpoint
		peers    map[string]struct{}
	}

	type tupleAgg struct {
		addr      netip.Addr
		withDNS   map[dnsKey]*agg
		synthetic *agg
	}

	best := make(map[tupleKey]*tupleAgg, len(entries))

	for _, e := range entries {
		if e.Port == 0 {
			continue
		}
		ip, ok := canonicalIPv4String(e.DestinationIP)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(e.Protocol))
		if proto == "" {
			continue
		}
		dnsName := canonicalDNSName(e.DNSName)

		tk := tupleKey{ip: ip, proto: proto, port: e.Port}
		group, exists := best[tk]
		if !exists {
			group = &tupleAgg{
				addr:    addr,
				withDNS: make(map[dnsKey]*agg, 2),
			}
			best[tk] = group
		}

		var cur *agg
		if dnsName == "" {
			if group.synthetic == nil {
				syntheticDNS := serviceEndpointPrivateServer
				if isPublicIPv4(addr) {
					syntheticDNS = serviceEndpointNoDNSAttribution
				}
				group.synthetic = &agg{
					endpoint: ServiceEndpoint{
						IP:       ip,
						DNS:      syntheticDNS,
						Protocol: proto,
						Port:     e.Port,
						HashVal:  serviceEndpointHash64(ip, syntheticDNS, proto, e.Port),
					},
					peers: make(map[string]struct{}, 4),
				}
			}
			cur = group.synthetic
		} else {
			dk := dnsKey{ip: ip, dns: dnsName, proto: proto, port: e.Port}
			cur, exists = group.withDNS[dk]
			if !exists {
				cur = &agg{
					endpoint: ServiceEndpoint{
						IP:       ip,
						DNS:      dnsName,
						Protocol: proto,
						Port:     e.Port,
						HashVal:  serviceEndpointHash64(ip, dnsName, proto, e.Port),
					},
					peers: make(map[string]struct{}, 4),
				}
				group.withDNS[dk] = cur
			}
		}

		obs := int64(0)
		if !e.ObservedAt.IsZero() {
			obs = e.ObservedAt.UTC().UnixMilli()
		}
		if cur.endpoint.ObservedAt == 0 || (obs > 0 && obs < cur.endpoint.ObservedAt) {
			cur.endpoint.ObservedAt = obs
		}

		issuer, ok := canonicalIPv4String(e.IssuerIP)
		if !ok {
			continue
		}
		issuerAddr, err := netip.ParseAddr(issuer)
		if err != nil || !issuerAddr.Is4() || isPublicIPv4(issuerAddr) {
			continue
		}
		cur.peers[issuer] = struct{}{}
	}

	out := make([]ServiceEndpoint, 0, len(best))
	for _, group := range best {
		if len(group.withDNS) > 0 {
			for _, v := range group.withDNS {
				v.endpoint.PeersCount = len(v.peers)
				out = append(out, v.endpoint)
			}
			continue
		}
		if group.synthetic != nil {
			group.synthetic.endpoint.PeersCount = len(group.synthetic.peers)
			out = append(out, group.synthetic.endpoint)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if out[i].DNS != out[j].DNS {
			return out[i].DNS < out[j].DNS
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})

	return out
}

func serviceEndpointHash64(ip, dns, proto string, port uint16) int64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d", ip, dns, proto, port)
	return int64(h.Sum64())
}
