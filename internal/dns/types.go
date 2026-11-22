// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
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
	mu          sync.RWMutex
	RequestTime captureTime
	wireEndpoints
	DNSNameID       uint64
	answers         resolvedAnswers
	CNAMETargets    []string
	DestinationPort *uint16

	PCAPFile   string          // for table output
	Candidates []ConnCandidate // filled in AttachConnectionsFromPCAPs

	// ObservedEndpointBindings records exact directly observed endpoint
	// connections for this DNS answer. Unlike DestinationPort/ProtocolL4, this
	// can hold multiple protocol/port observations for one DNS name -> IP
	// transaction. Only direct issuer+resolved-IP matches should populate it.
	ObservedEndpointBindings []ObservedEndpointBinding

	// By default this will be IssuerIP.String(), but when --radius-imsi is
	// enabled, and there is a matching IMSI, this will be that IMSI.
	IssuerLabel string

	// NameEvidence indicates how DNSName itself was sourced (dns vs sni).
	// For normal DNS transactions: EvDNSAnswer.
	// For synthetic SNI transactions: EvSNI.
	NameEvidence Evidence
	ProtocolL4   wireProtocol
}

// Used during pass 1 to match queries/responses
type TxKey struct {
	Identity string
	Issuer   string
	SrcPort  uint16
	Resolver string
	Proto    L4Proto
	ID       uint16
	NameID   uint64
}

// txLookupKey is the primary request/response correlation key:
// issuer(srcIP), issuer source port, resolver(dstIP), protocol, DNS ID.
// DNS name is intentionally excluded here and used as an optional secondary hint.
type txLookupKey struct {
	Identity string
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

// ObservedEndpointBinding is a durable exact endpoint observation associated
// with a DNS answer. ObservedAt is the packet observation timestamp used by the
// topology edge, so NTM matching can require the same observed event rather
// than broad tuple-only membership.
type ObservedEndpointBinding struct {
	DstIP      string
	Protocol   L4Proto
	Port       uint16
	ObservedAt time.Time
}

// Stats key: (DNS name, port)
type NamePortKey struct {
	Name string
	Port uint16
}

// AddCNAMETarget records a visible CNAME target from a DNS response.
func (tx *DNSTransaction) AddCNAMETarget(name string) {
	name = canonicalDNSName(name)
	if name == "" {
		return
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	for _, existing := range tx.CNAMETargets {
		if existing == name {
			return
		}
	}
	tx.CNAMETargets = append(tx.CNAMETargets, name)
}

// AddObservedEndpointBinding records a direct endpoint observation for this
// transaction and deduplicates exact duplicate dst/proto/port/timestamp values.
func (tx *DNSTransaction) AddObservedEndpointBinding(binding ObservedEndpointBinding) {
	ip, ok := canonicalIPv4String(binding.DstIP)
	if !ok || binding.Protocol == L4ProtoUnknown || binding.Port == 0 || binding.ObservedAt.IsZero() {
		return
	}
	binding.DstIP = ip
	binding.ObservedAt = binding.ObservedAt.UTC()

	tx.mu.Lock()
	defer tx.mu.Unlock()
	for _, existing := range tx.ObservedEndpointBindings {
		if existing.DstIP == binding.DstIP &&
			existing.Protocol == binding.Protocol &&
			existing.Port == binding.Port &&
			existing.ObservedAt.Equal(binding.ObservedAt) {
			return
		}
	}
	tx.ObservedEndpointBindings = append(tx.ObservedEndpointBindings, binding)
}

// HasObservedEndpointBinding reports whether this transaction has a direct
// endpoint observation matching the exact topology edge observation.
func (tx *DNSTransaction) HasObservedEndpointBinding(dstIP string, proto L4Proto, port uint16, observedAt time.Time) bool {
	ip, ok := canonicalIPv4String(dstIP)
	if !ok || proto == L4ProtoUnknown || port == 0 || observedAt.IsZero() {
		return false
	}
	observedAt = observedAt.UTC()

	tx.mu.RLock()
	defer tx.mu.RUnlock()
	for _, binding := range tx.ObservedEndpointBindings {
		if binding.DstIP == ip &&
			binding.Protocol == proto &&
			binding.Port == port &&
			binding.ObservedAt.Equal(observedAt) {
			return true
		}
	}
	return false
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

		issuer := tx.issuerIP().String()
		if issuer == "" {
			continue
		}

		for i := 0; i < tx.resolvedIPLen(); i++ {
			ip := tx.resolvedIPAt(i)
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
			return slice[i].RequestTime.compare(slice[j].RequestTime) < 0
		})
	}

	return idx
}
