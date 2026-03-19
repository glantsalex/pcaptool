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
	"sync"
	"time"
)

// L4Proto represents the layer-4 protocol of a correlated connection.
// It is stored on the DNS transaction after a successful correlation pass.
type L4Proto string

const (
	L4ProtoUnknown L4Proto = ""
	L4ProtoTCP     L4Proto = "tcp"
	L4ProtoUDP     L4Proto = "udp"
)

type DNSTransaction struct {
	mu              sync.RWMutex
	RequestTime     time.Time
	IssuerIP        net.IP
	DNSName         string
	ResolvedIPs     []net.IP
	ResolverIP      net.IP
	DestinationPort *uint16

	ProtocolL4 L4Proto // tcp/udp once correlation has chosen a candidate

	PCAPFile   string          // for table output
	Candidates []ConnCandidate // filled in AttachConnectionsFromPCAPs

	// By default this will be IssuerIP.String(), but when --radius-imsi is
	// enabled, and there is a matching IMSI, this will be that IMSI.
	IssuerLabel string

	// NameEvidence indicates how DNSName itself was sourced (dns vs sni).
	// For normal DNS transactions: EvDNSAnswer.
	// For synthetic SNI transactions: EvSNI.
	NameEvidence Evidence

	// ResolvedIPEvidence maps ip.String() -> evidence flags for that DNSName<->IP mapping.
	ResolvedIPEvidence map[string]Evidence
}

// Used during pass 1 to match queries/responses
type TxKey struct {
	Issuer   string
	SrcPort  uint16
	Resolver string
	Proto    L4Proto
	ID       uint16
	Name     string
}

// txLookupKey is the primary request/response correlation key:
// issuer(srcIP), issuer source port, resolver(dstIP), protocol, DNS ID.
// DNS name is intentionally excluded here and used as an optional secondary hint.
type txLookupKey struct {
	Issuer   string
	SrcPort  uint16
	Resolver string
	Proto    L4Proto
	ID       uint16
}

func makeTxLookupKey(issuer string, srcPort uint16, resolver string, proto L4Proto, id uint16) txLookupKey {
	return txLookupKey{
		Issuer:   issuer,
		SrcPort:  srcPort,
		Resolver: resolver,
		Proto:    proto,
		ID:       id,
	}
}

// Used by the index: (issuer,dstIP)
type idxKey struct {
	Issuer string
	Dst    string
}

// DNS-centric connection candidate
type ConnCandidate struct {
	Port  uint16
	DT    time.Duration // connection_time - dns_request_time
	Proto L4Proto
}

// Stats key: (DNS name, port)
type NamePortKey struct {
	Name string
	Port uint16
}

func (tx *DNSTransaction) ensureEvidenceMap() {
	if tx.ResolvedIPEvidence == nil {
		tx.ResolvedIPEvidence = make(map[string]Evidence, 4)
	}
}

func (tx *DNSTransaction) addResolvedIPLocked(ip net.IP, ev Evidence) {
	if ip == nil {
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	s := ip4.String()

	for _, existing := range tx.ResolvedIPs {
		if existing != nil && existing.To4() != nil && existing.Equal(ip4) {
			tx.ensureEvidenceMap()
			tx.ResolvedIPEvidence[s] |= ev
			return
		}
	}
	tx.ResolvedIPs = append(tx.ResolvedIPs, append(net.IP(nil), ip4...))
	tx.ensureEvidenceMap()
	tx.ResolvedIPEvidence[s] |= ev
}

// AddResolvedIP adds ip to ResolvedIPs if missing and ORs evidence flags.
func (tx *DNSTransaction) AddResolvedIP(ip net.IP, ev Evidence) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.addResolvedIPLocked(ip, ev)
}

// MarkObservedConn ORs EvObservedConn for ip if present; if ip missing and allowAdd is true, it will add it.
func (tx *DNSTransaction) MarkObservedConn(ip net.IP, allowAdd bool) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if ip == nil {
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	s := ip4.String()

	for _, existing := range tx.ResolvedIPs {
		if existing != nil && existing.To4() != nil && existing.Equal(ip4) {
			tx.ensureEvidenceMap()
			tx.ResolvedIPEvidence[s] |= EvObservedConn
			return
		}
	}
	if allowAdd {
		tx.addResolvedIPLocked(ip4, EvConnInferred|EvObservedConn|tx.NameEvidence)
	}
}

func (tx *DNSTransaction) ResolvedIPCount() int {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return len(tx.ResolvedIPs)
}

// Simple index: (issuer,dst) -> []*DNSTransaction
type TxIndex map[idxKey][]*DNSTransaction

func BuildTxnIndex(txs []*DNSTransaction) TxIndex {
	idx := make(TxIndex)

	for _, tx := range txs {
		// If DestinationPort is already set, this transaction is "fully resolved"
		// (e.g. from TLS SNI synthetic tx). We do NOT want to feed it back into
		// the connection-correlation logic.
		if tx.DestinationPort != nil && *tx.DestinationPort > 0 {
			continue
		}

		issuer := tx.IssuerIP.String()
		if issuer == "" {
			continue
		}

		for _, ip := range tx.ResolvedIPs {
			ipStr := ip.String()
			if ipStr == "" {
				continue
			}
			k := idxKey{Issuer: issuer, Dst: ipStr}
			idx[k] = append(idx[k], tx)
		}
	}

	// Ensure deterministic ordering per (issuer,dst): sort by RequestTime.
	for k := range idx {
		slice := idx[k]
		sort.Slice(slice, func(i, j int) bool {
			return slice[i].RequestTime.Before(slice[j].RequestTime)
		})
	}

	return idx
}
