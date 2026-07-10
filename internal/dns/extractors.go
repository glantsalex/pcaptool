// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketExtractor is a per-file packet consumer.
// It must be single-file state (no locks needed inside extractors).
type PacketExtractor interface {
	Name() string
	OnPacket(pkt gopacket.Packet, fileBase string)
	Earliest() time.Time
}

// TruncatedDNSPacket describes a UDP/IPv4 DNS query whose QNAME was not fully
// present in the captured UDP payload. It is diagnostic-only and is never used
// to create or enrich a DNSTransaction.
type TruncatedDNSPacket struct {
	PCAPFile         string
	IssuerIP         string
	TruncatedDNSName string
	TimestampUTC     time.Time
	SrcIP            string
	DstIP            string
	SrcPort          uint16
	DstPort          uint16
	TxID             uint16
	Reason           string
}

// -------------------------
// DNS extractor (queries/responses → DNSTransaction map)
// -------------------------

type dnsExtractor struct {
	txMap                          map[TxKey][]*DNSTransaction
	byLookup                       map[txLookupKey][]*DNSTransaction
	truncatedDNSPackets            []TruncatedDNSPacket
	collectTruncatedDNSDiagnostics bool
	earliest                       time.Time
	first                          bool
}

func newDNSExtractor() *dnsExtractor {
	return newDNSExtractorWithDiagnostics(false)
}

func newDNSExtractorWithDiagnostics(collectTruncatedDNS bool) *dnsExtractor {
	return &dnsExtractor{
		txMap:                          make(map[TxKey][]*DNSTransaction),
		byLookup:                       make(map[txLookupKey][]*DNSTransaction),
		collectTruncatedDNSDiagnostics: collectTruncatedDNS,
		first:                          true,
	}
}

func (e *dnsExtractor) Name() string { return "dns" }
func (e *dnsExtractor) Earliest() time.Time {
	if e.first {
		return time.Time{}
	}
	return e.earliest
}

func (e *dnsExtractor) Map() map[TxKey][]*DNSTransaction { return e.txMap }

func (e *dnsExtractor) TruncatedDNSPackets() []TruncatedDNSPacket {
	return e.truncatedDNSPackets
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
}

func pickResponseTx(cands []*DNSTransaction, respName string, respTS time.Time) *DNSTransaction {
	respName = canonicalDNSName(respName)

	// Prefer exact name match when response question name is available.
	for i := len(cands) - 1; i >= 0; i-- {
		tx := cands[i]
		if tx == nil || tx.RequestTime.After(respTS) {
			continue
		}
		if respName == "" || tx.DNSName == respName {
			return tx
		}
	}

	// Fallback: same tuple match without response name.
	if respName != "" {
		for i := len(cands) - 1; i >= 0; i-- {
			tx := cands[i]
			if tx == nil || tx.RequestTime.After(respTS) {
				continue
			}
			return tx
		}
	}

	return nil
}

func addDNSTransaction(
	txMap map[TxKey][]*DNSTransaction,
	byLookup map[txLookupKey][]*DNSTransaction,
	key TxKey,
	tx *DNSTransaction,
) {
	txMap[key] = append(txMap[key], tx)
	lk := makeTxLookupKey(key.Issuer, key.SrcPort, key.Resolver, key.Proto, key.ID)
	byLookup[lk] = append(byLookup[lk], tx)
}

func newResponseOnlyDNSTransaction(ts time.Time, issuerIP, resolverIP net.IP, dnsName, fileBase string, answers []net.IP) *DNSTransaction {
	dnsName = canonicalDNSName(dnsName)
	if dnsName == "" || len(answers) == 0 {
		return nil
	}
	tx := &DNSTransaction{
		RequestTime:  ts.UTC(),
		IssuerIP:     append(net.IP(nil), issuerIP...),
		DNSName:      dnsName,
		ResolverIP:   append(net.IP(nil), resolverIP...),
		NameEvidence: EvDNSAnswer,
		PCAPFile:     filepath.Base(fileBase),
	}
	for _, ip := range answers {
		tx.AddResolvedIP(ip, EvDNSAnswer)
	}
	if len(tx.ResolvedIPs) == 0 {
		return nil
	}
	return tx
}

func (e *dnsExtractor) OnPacket(pkt gopacket.Packet, fileBase string) {
	md := pkt.Metadata()
	if md == nil {
		return
	}
	ts := md.Timestamp
	if e.first || ts.Before(e.earliest) {
		e.earliest = ts
		e.first = false
	}

	// IPs (v4 or v6)
	ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip4Layer == nil && ip6Layer == nil {
		return
	}

	var srcIP, dstIP net.IP
	if ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		srcIP, dstIP = ip4.SrcIP, ip4.DstIP
	} else {
		ip6 := ip6Layer.(*layers.IPv6)
		srcIP, dstIP = ip6.SrcIP, ip6.DstIP
	}

	// Correlation key components from transport layer.
	var (
		proto   L4Proto
		srcPort uint16
		dstPort uint16
		payload []byte
	)
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		proto = L4ProtoUDP
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		payload = udp.Payload
	} else if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		proto = L4ProtoTCP
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		payload = tcp.Payload
	} else {
		return
	}

	if ip4Layer != nil && proto == L4ProtoUDP && (srcPort == 53 || dstPort == 53) {
		if id, name, reason, ok := extractTruncatedDNSQueryDiagnostic(payload); ok {
			if e.collectTruncatedDNSDiagnostics {
				e.truncatedDNSPackets = append(e.truncatedDNSPackets, TruncatedDNSPacket{
					PCAPFile:         filepath.Base(fileBase),
					IssuerIP:         srcIP.String(),
					TruncatedDNSName: name,
					TimestampUTC:     ts.UTC(),
					SrcIP:            srcIP.String(),
					DstIP:            dstIP.String(),
					SrcPort:          srcPort,
					DstPort:          dstPort,
					TxID:             id,
					Reason:           reason,
				})
			}
			// Incomplete QNAMEs are diagnostic-only. Do not let them reach the
			// normal DNS layer or raw-query transaction paths.
			return
		}
	}

	// We only care about DNS layer packets.
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	d, _ := dnsLayer.(*layers.DNS)

	captureTruncated := md.Truncated || (md.CaptureInfo.Length > 0 && md.CaptureInfo.CaptureLength < md.CaptureInfo.Length)

	// --- Queries ---
	if d != nil && !d.QR && len(d.Questions) > 0 {
		q := d.Questions[0]
		if q.Type != layers.DNSTypeA {
			return
		}
		dnsName := canonicalDNSName(string(q.Name))
		if dnsName == "" {
			return
		}
		key := TxKey{
			Issuer:   srcIP.String(),
			SrcPort:  srcPort,
			Resolver: dstIP.String(),
			Proto:    proto,
			ID:       d.ID,
			Name:     dnsName,
		}

		tx := &DNSTransaction{
			RequestTime: ts.UTC(),
			IssuerIP:    append(net.IP(nil), srcIP...),
			DNSName:     dnsName,
			ResolverIP:  append(net.IP(nil), dstIP...),
			PCAPFile:    filepath.Base(fileBase),
		}
		addDNSTransaction(e.txMap, e.byLookup, key, tx)
		return
	}

	// Truncated-query fallback:
	// If normal DNS question parsing is unavailable (or empty) on a capture-truncated
	// client->resolver query packet, decode the first QNAME from raw bytes.
	if captureTruncated && dstPort == 53 && (d == nil || (!d.QR && len(d.Questions) == 0)) {
		if id, dnsName, ok := extractDNSQueryNameFromRaw(payload, proto, true); ok {
			key := TxKey{
				Issuer:   srcIP.String(),
				SrcPort:  srcPort,
				Resolver: dstIP.String(),
				Proto:    proto,
				ID:       id,
				Name:     dnsName,
			}
			tx := &DNSTransaction{
				RequestTime: ts.UTC(),
				IssuerIP:    append(net.IP(nil), srcIP...),
				DNSName:     dnsName,
				ResolverIP:  append(net.IP(nil), dstIP...),
				PCAPFile:    filepath.Base(fileBase),
			}
			addDNSTransaction(e.txMap, e.byLookup, key, tx)
			return
		}
	}

	// --- Responses ---
	if (d != nil && d.QR) || (captureTruncated && srcPort == 53) {
		var (
			answers               []net.IP
			respName              string
			respID                uint16
			canCreateResponseOnly bool
		)

		if d != nil && d.QR {
			respID = d.ID
			if len(d.Questions) > 0 {
				respName = canonicalDNSName(string(d.Questions[0].Name))
				canCreateResponseOnly = respName != "" && d.Questions[0].Type == layers.DNSTypeA
			}
		}

		if d != nil && d.QR {
			for _, ans := range d.Answers {
				if ans.Type == layers.DNSTypeA && len(ans.IP) > 0 {
					answers = append(answers, append(net.IP(nil), ans.IP...))
				}
			}
		}

		if captureTruncated && srcPort == 53 {
			rawID, rawName, rawAnswers, ok := extractDNSResponseFromRaw(payload, proto, true)
			if ok {
				if respID == 0 {
					respID = rawID
				}
				if respName == "" {
					respName = rawName
				}
				if rawName != "" {
					canCreateResponseOnly = true
				}
				answers = append(answers, rawAnswers...)
			}
		}

		if respID == 0 || len(answers) == 0 {
			return
		}

		lk := makeTxLookupKey(
			dstIP.String(), // original query src
			dstPort,        // original query src port
			srcIP.String(), // original query dst
			proto,
			respID,
		)
		cands := e.byLookup[lk]
		tx := pickResponseTx(cands, respName, ts.UTC())
		if tx == nil {
			if !canCreateResponseOnly {
				return
			}
			tx = newResponseOnlyDNSTransaction(ts, dstIP, srcIP, respName, fileBase, answers)
			if tx == nil {
				return
			}
			key := TxKey{
				Issuer:   dstIP.String(),
				SrcPort:  dstPort,
				Resolver: srcIP.String(),
				Proto:    proto,
				ID:       respID,
				Name:     respName,
			}
			addDNSTransaction(e.txMap, e.byLookup, key, tx)
			return
		}

		// Ensure name evidence is set (defensive)
		if tx.NameEvidence == EvNone {
			tx.NameEvidence = EvDNSAnswer
		}

		for _, ip := range answers {
			tx.AddResolvedIP(ip, EvDNSAnswer) // records source per-IP
		}

		if len(tx.ResolvedIPs) > 0 {
			tx.ResolverIP = append(net.IP(nil), srcIP...)
		}
	}
}

func extractDNSQueryNameFromRaw(payload []byte, proto L4Proto, captureTruncated bool) (uint16, string, bool) {
	msg, ok := dnsMessageFromPayload(payload, proto)
	if !ok {
		return 0, "", false
	}

	if len(msg) < 12 {
		return 0, "", false
	}

	id := binary.BigEndian.Uint16(msg[:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qr := flags&0x8000 != 0
	if qr {
		return 0, "", false
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 {
		return 0, "", false
	}

	name, off, complete, ok := parseRawDNSQuestionName(msg, 12)
	if !ok || name == "" {
		return 0, "", false
	}

	// If QTYPE is present, keep only A queries.
	if off+4 <= len(msg) {
		qType := binary.BigEndian.Uint16(msg[off : off+2])
		if qType != uint16(layers.DNSTypeA) {
			return 0, "", false
		}
	} else if complete && !captureTruncated {
		// Name was complete but QTYPE/QCLASS is missing and packet wasn't marked
		// truncated: treat as malformed.
		return 0, "", false
	}

	return id, canonicalDNSName(name), true
}

const (
	truncatedDNSReasonLabel              = "truncated_label"
	truncatedDNSReasonMissingRoot        = "missing_root_label"
	truncatedDNSReasonCompressionPointer = "unsupported_compression_pointer"
)

func extractTruncatedDNSQueryDiagnostic(payload []byte) (uint16, string, string, bool) {
	if len(payload) < 12 {
		return 0, "", "", false
	}

	id := binary.BigEndian.Uint16(payload[:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 {
		return 0, "", "", false
	}
	if binary.BigEndian.Uint16(payload[4:6]) == 0 {
		return 0, "", "", false
	}

	name, reason, ok := extractTruncatedDNSQName(payload)
	if !ok {
		return 0, "", "", false
	}
	return id, canonicalDNSName(name), reason, true
}

// extractTruncatedDNSQName returns only QNAME prefixes proven to be present in
// msg. A normally terminated QNAME is complete and therefore not diagnostic.
func extractTruncatedDNSQName(msg []byte) (string, string, bool) {
	if len(msg) < 12 {
		return "", "", false
	}

	labels := make([]string, 0, 8)
	off := 12
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return strings.Join(labels, "."), truncatedDNSReasonMissingRoot, true
		}

		labelLen := int(msg[off])
		off++
		if labelLen == 0 {
			return "", "", false
		}
		if labelLen&0xC0 == 0xC0 {
			if len(labels) == 0 {
				return "", "", false
			}
			return strings.Join(labels, "."), truncatedDNSReasonCompressionPointer, true
		}
		if labelLen&0xC0 != 0 || labelLen > 63 {
			return "", "", false
		}

		if off+labelLen > len(msg) {
			if off < len(msg) {
				if label, valid := parseDNSLabelASCII(msg[off:]); valid && label != "" {
					labels = append(labels, label)
				}
			}
			return strings.Join(labels, "."), truncatedDNSReasonLabel, true
		}

		label, valid := parseDNSLabelASCII(msg[off : off+labelLen])
		if !valid || label == "" {
			return "", "", false
		}
		labels = append(labels, label)
		off += labelLen
	}

	return "", "", false
}

func extractDNSResponseFromRaw(payload []byte, proto L4Proto, captureTruncated bool) (uint16, string, []net.IP, bool) {
	msg, ok := dnsMessageFromPayload(payload, proto)
	if !ok || len(msg) < 12 {
		return 0, "", nil, false
	}

	id := binary.BigEndian.Uint16(msg[:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return 0, "", nil, false
	}

	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return 0, "", nil, false
	}

	off := 12
	respName := ""
	for i := 0; i < qdCount; i++ {
		name, next, _, ok := parseRawDNSQuestionName(msg, off)
		if !ok {
			if i == 0 && captureTruncated {
				break
			}
			return 0, "", nil, false
		}
		if i == 0 {
			respName = canonicalDNSName(name)
		}
		off = next
		if off+4 > len(msg) {
			return 0, "", nil, false
		}
		if i == 0 {
			qType := binary.BigEndian.Uint16(msg[off : off+2])
			if qType != uint16(layers.DNSTypeA) {
				return 0, "", nil, false
			}
		}
		off += 4
	}

	answers := make([]net.IP, 0, anCount)
	for i := 0; i < anCount; i++ {
		next, ok := skipRawDNSName(msg, off)
		if !ok {
			break
		}
		off = next

		if off+10 > len(msg) {
			break
		}

		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rrClass := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdLength := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10

		if rdLength < 0 || off+rdLength > len(msg) {
			break
		}

		if rrClass == 1 && rrType == uint16(layers.DNSTypeA) && rdLength == 4 {
			ip := net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3]).To4()
			if ip != nil {
				answers = append(answers, append(net.IP(nil), ip...))
			}
		}
		off += rdLength
	}

	if len(answers) == 0 {
		return 0, "", nil, false
	}
	return id, respName, answers, true
}

func dnsMessageFromPayload(payload []byte, proto L4Proto) ([]byte, bool) {
	msg := payload
	if len(msg) == 0 {
		return nil, false
	}

	if proto == L4ProtoTCP {
		// DNS over TCP starts with 2-byte message length prefix.
		if len(msg) < 2 {
			return nil, false
		}
		dnsLen := int(binary.BigEndian.Uint16(msg[:2]))
		msg = msg[2:]
		if dnsLen <= 0 {
			return nil, false
		}
		if dnsLen < len(msg) {
			msg = msg[:dnsLen]
		}
	}

	return msg, true
}

func parseRawDNSQuestionName(msg []byte, off int) (name string, next int, complete bool, ok bool) {
	labels := make([]string, 0, 8)
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			if len(labels) == 0 {
				return "", off, false, false
			}
			return strings.Join(labels, "."), off, false, true
		}

		l := int(msg[off])
		off++

		if l == 0 {
			if len(labels) == 0 {
				return "", off, true, false
			}
			return strings.Join(labels, "."), off, true, true
		}

		// Conservative fallback: don't follow compression pointers in queries.
		if l&0xC0 != 0 {
			return "", off, false, false
		}
		if l > 63 {
			return "", off, false, false
		}

		if off+l > len(msg) {
			// Truncated in the middle of a label: salvage what we have.
			if off < len(msg) {
				lbl, ok := parseDNSLabelASCII(msg[off:len(msg)])
				if ok && lbl != "" {
					labels = append(labels, lbl)
				}
			}
			if len(labels) == 0 {
				return "", len(msg), false, false
			}
			return strings.Join(labels, "."), len(msg), false, true
		}

		lbl, ok := parseDNSLabelASCII(msg[off : off+l])
		if !ok || lbl == "" {
			return "", off, false, false
		}
		labels = append(labels, lbl)
		off += l
	}

	return "", off, false, false
}

func skipRawDNSName(msg []byte, off int) (int, bool) {
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return off, false
		}

		l := int(msg[off])
		off++

		if l == 0 {
			return off, true
		}

		if l&0xC0 == 0xC0 {
			if off >= len(msg) {
				return off, false
			}
			return off + 1, true
		}
		if l&0xC0 != 0 {
			return off, false
		}
		if l > 63 {
			return off, false
		}
		if off+l > len(msg) {
			return off, false
		}
		off += l
	}

	return off, false
}

func parseDNSLabelASCII(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c >= 'a' && c <= 'z':
			out = append(out, c)
		case c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-' || c == '_':
			out = append(out, c)
		default:
			return "", false
		}
	}
	return string(out), true
}

// -------------------------
// TLS SNI extractor (ClientHello → synthetic DNSTransaction slice)
// -------------------------

type sniExtractor struct {
	out      []*DNSTransaction
	earliest time.Time
	first    bool

	// Per-file dedup (retransmits) by issuer+dstIP+port+sni
	seen map[sniKey]struct{}
}

type sniKey struct {
	issuer string
	dstIP  string
	port   uint16
	sni    string
}

func newSNIExtractor() *sniExtractor {
	return &sniExtractor{
		first: true,
		seen:  make(map[sniKey]struct{}),
	}
}

func (e *sniExtractor) Name() string { return "tls-sni" }
func (e *sniExtractor) Earliest() time.Time {
	if e.first {
		return time.Time{}
	}
	return e.earliest
}

func (e *sniExtractor) Slice() []*DNSTransaction { return e.out }

func (e *sniExtractor) OnPacket(pkt gopacket.Packet, fileBase string) {
	md := pkt.Metadata()
	if md == nil {
		return
	}
	ts := md.Timestamp
	if e.first || ts.Before(e.earliest) {
		e.earliest = ts
		e.first = false
	}

	// Skip truncated packets for SNI parsing.
	if md.Truncated {
		return
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)
	if len(tcp.Payload) == 0 {
		return
	}

	sni, ok := extractSNIFromClientHello(tcp.Payload)
	if !ok || sni == "" {
		return
	}

	networkLayer := pkt.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP net.IP
	switch nl := networkLayer.(type) {
	case *layers.IPv4:
		srcIP, dstIP = nl.SrcIP, nl.DstIP
	case *layers.IPv6:
		srcIP, dstIP = nl.SrcIP, nl.DstIP
	default:
		return
	}
	if srcIP == nil || dstIP == nil {
		return
	}

	port := uint16(tcp.DstPort)
	if port == 0 {
		return
	}

	k := sniKey{
		issuer: srcIP.String(),
		dstIP:  dstIP.String(),
		port:   port,
		sni:    sni,
	}
	if _, exists := e.seen[k]; exists {
		return
	}
	e.seen[k] = struct{}{}

	dp := port
	tx := &DNSTransaction{
		RequestTime:     ts.UTC(),
		IssuerIP:        append(net.IP(nil), srcIP...),
		DNSName:         sni,
		ResolvedIPs:     []net.IP{append(net.IP(nil), dstIP...)},
		ResolverIP:      nil,
		DestinationPort: &dp, // already resolved for synthetic tx
		PCAPFile:        filepath.Base(fileBase),
		Candidates:      nil,
		ProtocolL4:      L4ProtoTCP,
	}

	e.out = append(e.out, tx)
}
