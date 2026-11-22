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

// mergeDNSTransactionIntoBucket keeps distinct per-key query instances while
// still coalescing exact duplicate instances (same request timestamp).
func mergeDNSTransactionIntoBucket(bucket []*DNSTransaction, in *DNSTransaction) []*DNSTransaction {
	if in == nil {
		return bucket
	}

	for _, cur := range bucket {
		if cur == nil {
			continue
		}
		// Same key + same request timestamp => same logical transaction instance.
		if cur.RequestTime.Equal(in.RequestTime) {
			mergeDNSTransaction(cur, in)
			return bucket
		}
	}

	return append(bucket, in)
}

func sortTxBucketByTime(bucket []*DNSTransaction) {
	sort.Slice(bucket, func(i, j int) bool {
		return bucket[i].RequestTime.Before(bucket[j].RequestTime)
	})
}

func mergeDNSTransaction(dst, src *DNSTransaction) {
	if dst == nil || src == nil {
		return
	}

	if dst.RequestTime.IsZero() || (!src.RequestTime.IsZero() && src.RequestTime.Before(dst.RequestTime)) {
		dst.RequestTime = src.RequestTime
	}
	if src.PCAPFile < dst.PCAPFile {
		dst.PCAPFile = src.PCAPFile
	}
	if dst.NameEvidence == EvNone && src.NameEvidence != EvNone {
		dst.NameEvidence = src.NameEvidence
	}

	for i := 0; i < src.resolvedIPLen(); i++ {
		ip := src.resolvedIPAt(i)
		ip4 := ip.To4()
		if ip4.isNil() {
			continue
		}

		ev := EvNone
		if src.hasResolvedIPEvidence() {
			ev = src.resolvedIPEvidenceValue(ip4.String())
		}
		if ev == EvNone {
			ev = src.NameEvidence
			if ev == EvNone {
				ev = EvDNSAnswer
			}
		}
		dst.addResolvedIPView(ip4, ev)
	}
	for _, cname := range src.CNAMETargets {
		dst.AddCNAMETarget(cname)
	}
	for _, binding := range src.ObservedEndpointBindings {
		dst.AddObservedEndpointBinding(binding)
	}

	if dst.ResolverIP == nil && src.ResolverIP != nil {
		dst.ResolverIP = append(net.IP(nil), src.ResolverIP...)
	}
}
