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

	pce "github.com/aglants/pcaptool/internal/pcap"
)

// key for DNS query/response matching
type txKey struct {
	Issuer   string
	Resolver string
	ID       uint16
	Name     string
}

func BuildTransactionsFromEvents(events []pce.Event) ([]*DNSTransaction, error) {
	txMap := make(map[txKey]*DNSTransaction)

	for _, ev := range events {
		switch ev.Type {
		case pce.EventDNSQuery:
			if !ev.DNSQTypeA {
				continue
			}
			key := txKey{
				Issuer:   ev.SrcIP.String(),
				Resolver: ev.DstIP.String(),
				ID:       ev.DNSID,
				Name:     ev.DNSQName,
			}
			if _, exists := txMap[key]; !exists {
				txMap[key] = &DNSTransaction{
					RequestTime: ev.Timestamp.UTC(),
					IssuerIP:    append([]byte{}, ev.SrcIP...),
					DNSName:     ev.DNSQName,
				}
			}
		case pce.EventDNSResponse:
			if !ev.DNSIsReply || len(ev.DNSAAnswers) == 0 {
				continue
			}

			key := txKey{
				Issuer:   ev.DstIP.String(), // response src/dst reversed
				Resolver: ev.SrcIP.String(),
				ID:       ev.DNSID,
				// Name not available here; match only by IDs & IPs for now.
			}

			// Try to find any tx starting with same issuer/resolver/ID
			var found *DNSTransaction
			for k, tx := range txMap {
				if k.Issuer == key.Issuer && k.Resolver == key.Resolver && k.ID == key.ID {
					found = tx
					break
				}
			}
			if found == nil {
				// No matching query seen; best-effort partial transaction.
				// Log or ignore; here we ignore to keep output "query-centric".
				continue
			}

			// Append answers
			for _, ip := range ev.DNSAAnswers {
				found.ResolvedIPs = append(found.ResolvedIPs, append([]byte{}, ip...))
			}
			if len(found.ResolvedIPs) > 0 {
				found.ResolverIP = append(net.IP{}, ev.SrcIP...)
			}
		}
	}

	var txs []*DNSTransaction
	for _, tx := range txMap {
		txs = append(txs, tx)
	}

	// Sort by RequestTime
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].RequestTime.Before(txs[j].RequestTime)
	})

	return txs, nil
}
