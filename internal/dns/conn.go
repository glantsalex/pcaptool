// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	pce "github.com/aglants/pcaptool/internal/pcap"
)

// AttachConnections finds first connection to a resolved IP per transaction.
func AttachConnections(events []pce.Event, txs []*DNSTransaction) error {
	// Precollect connection events
	var conns []pce.Event
	for _, ev := range events {
		if ev.Type == pce.EventConnection {
			conns = append(conns, ev)
		}
	}

	ci := 0
	for _, tx := range txs {
		if tx.resolvedIPLen() == 0 {
			continue
		}
		issuer := tx.issuerIP().String()

		ipSet := make(map[string]struct{}, tx.resolvedIPLen())
		for i := 0; i < tx.resolvedIPLen(); i++ {
			ip := tx.resolvedIPAt(i)
			ipSet[ip.String()] = struct{}{}
		}

		for ci < len(conns) && conns[ci].Timestamp.Before(tx.RequestTime.utc()) {
			ci++
		}

		for j := ci; j < len(conns); j++ {
			c := conns[j]
			if !c.Timestamp.After(tx.RequestTime.utc()) {
				continue
			}
			if c.SrcIP.String() != issuer {
				continue
			}
			if _, ok := ipSet[c.DstIP.String()]; !ok {
				continue
			}
			port := int(c.DstPort)
			tx.DestinationPort = (*uint16)(new(uint16))
			*tx.DestinationPort = uint16(port)
			break
		}
	}

	return nil
}
