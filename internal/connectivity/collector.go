// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package connectivity

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// L4Proto is the L4 protocol label used in the topology matrix.
type L4Proto string

const (
	ProtoTCP L4Proto = "tcp"
	ProtoUDP L4Proto = "udp"
)

type Edge struct {
	// IssuerIdentity scopes observations before pruning: IMSI or raw-IP fallback.
	// Empty means legacy, unpartitioned collection. IssuerIP remains the raw IP.
	IssuerIdentity string
	IssuerIP       string
	DstIP          string
	Protocol       L4Proto
	Port           uint16
	FirstSeen      time.Time
	ObservedTimes  ObservationHistory
}

const maxEdgeObservedTimes = 128

type Options struct {
	// Contact consumes an admitted observation synchronously in the file worker.
	// When supplied, no transport edge or timestamp history is retained.
	Contact func(identity, issuer, dst string, proto L4Proto, port uint16, ts time.Time, confirmed bool)
	// IssuerIdentity resolves the issuer at each observation time. It must be
	// safe for concurrent calls when shared by file collectors. Nil preserves
	// legacy grouping; an empty result in scoped mode uses the raw IP.
	IssuerIdentity         func(string, time.Time) string
	PendingTTL             time.Duration
	SweepEvery             time.Duration
	ExcludedDstPorts       map[uint16]struct{}
	CollapseFTPPassive     bool
	FTPPassiveMinPort      uint16
	FTPControlPorts        map[uint16]struct{}
	EnforcePrivateAsSource bool
}

func DefaultOptions() Options {
	return Options{
		PendingTTL:         30 * time.Second,
		SweepEvery:         2 * time.Second,
		CollapseFTPPassive: true,
		FTPPassiveMinPort:  30000,
		FTPControlPorts: map[uint16]struct{}{
			21:  {},
			990: {},
		},
	}
}

type pairKey struct {
	identity string
	issuer   string
	dst      string
}

type Collector struct {
	opt Options

	tcpSyn   map[tcpKey]time.Time
	udpFirst map[udpKey]time.Time

	edges map[edgeKey]ObservationHistory

	lastSweep time.Time

	ftpControlSeen map[pairKey]struct{}
	ftpPassivePend map[pairKey]time.Time
	ftpPassivePort map[edgeKey]time.Time
}

type tcpKey struct {
	cip      string
	sip      string
	cpt      uint16
	spt      uint16
	identity string
}

type udpKey = tcpKey

type edgeKey struct {
	identity string
	issuer   string
	dst      string
	proto    L4Proto
	port     uint16
}

func NewCollector(opt Options) *Collector {
	defaults := DefaultOptions()
	if opt.PendingTTL <= 0 {
		opt.PendingTTL = defaults.PendingTTL
	}
	if opt.SweepEvery <= 0 {
		opt.SweepEvery = defaults.SweepEvery
	}
	if opt.FTPPassiveMinPort == 0 {
		opt.FTPPassiveMinPort = defaults.FTPPassiveMinPort
	}
	if opt.FTPControlPorts == nil {
		opt.FTPControlPorts = defaults.FTPControlPorts
	}
	ftpControlPorts := make(map[uint16]struct{}, len(opt.FTPControlPorts))
	for port := range opt.FTPControlPorts {
		ftpControlPorts[port] = struct{}{}
	}
	opt.FTPControlPorts = ftpControlPorts
	var edges map[edgeKey]ObservationHistory
	if opt.Contact == nil {
		edges = make(map[edgeKey]ObservationHistory, 32768)
	}
	return &Collector{
		opt:            opt,
		tcpSyn:         make(map[tcpKey]time.Time, 8192),
		udpFirst:       make(map[udpKey]time.Time, 8192),
		edges:          edges,
		ftpControlSeen: make(map[pairKey]struct{}, 1024),
		ftpPassivePend: make(map[pairKey]time.Time, 256),
		ftpPassivePort: make(map[edgeKey]time.Time, 512),
	}
}

func (c *Collector) OnPacket(pkt gopacket.Packet, ts time.Time) {
	if c.lastSweep.IsZero() || ts.Sub(c.lastSweep) >= c.opt.SweepEvery {
		c.sweep(ts)
		c.lastSweep = ts
	}

	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}

	var srcIP, dstIP net.IP
	switch ip := nl.(type) {
	case *layers.IPv4:
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	case *layers.IPv6:
		return
	default:
		return
	}

	tl := pkt.TransportLayer()
	if tl == nil {
		return
	}

	switch t := tl.(type) {
	case *layers.TCP:
		c.onTCP(srcIP, dstIP, t, ts)
	case *layers.UDP:
		c.onUDP(srcIP, dstIP, t, ts)
	}
}

func (c *Collector) Edges() []Edge {
	out := make([]Edge, 0, len(c.edges))
	for k, times := range c.edges {
		if times.Len() == 0 {
			continue
		}
		out = append(out, Edge{
			IssuerIdentity: k.identity,
			IssuerIP:       k.issuer,
			DstIP:          k.dst,
			Protocol:       k.proto,
			Port:           k.port,
			FirstSeen:      times.At(0),
			ObservedTimes:  times.Clone(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		if out[i].DstIP != out[j].DstIP {
			return out[i].DstIP < out[j].DstIP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].IssuerIdentity < out[j].IssuerIdentity
	})

	return out
}

func (c *Collector) EdgesByFirstSeen() []Edge {
	out := make([]Edge, 0, len(c.edges))
	for k, times := range c.edges {
		if times.Len() == 0 {
			continue
		}
		out = append(out, Edge{
			IssuerIdentity: k.identity,
			IssuerIP:       k.issuer,
			DstIP:          k.dst,
			Protocol:       k.proto,
			Port:           k.port,
			FirstSeen:      times.At(0),
			ObservedTimes:  times.Clone(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		if out[i].DstIP != out[j].DstIP {
			return out[i].DstIP < out[j].DstIP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].IssuerIdentity < out[j].IssuerIdentity
	})

	return out
}

// MergeEdgeObservedTimes keeps a bounded set of edge observations: the earliest
// timestamp for stable first-seen semantics plus the latest observations for
// later DNS attribution checks.
func MergeEdgeObservedTimes(existing []time.Time, additions ...time.Time) []time.Time {
	times := append([]time.Time(nil), existing...)
	for _, ts := range additions {
		if ts.IsZero() {
			continue
		}
		utc := ts.UTC()
		duplicate := false
		for _, existingTS := range times {
			if existingTS.Equal(utc) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		times = append(times, utc)
	}
	if len(times) == 0 {
		return nil
	}
	sort.Slice(times, func(i, j int) bool {
		return times[i].Before(times[j])
	})
	if len(times) <= maxEdgeObservedTimes {
		return times
	}

	// Preserve the true first observation and the most recent observations.
	out := make([]time.Time, 0, maxEdgeObservedTimes)
	out = append(out, times[0])
	out = append(out, times[len(times)-(maxEdgeObservedTimes-1):]...)
	return out
}

func (c *Collector) recordEdgeObservation(ek edgeKey, ts time.Time, confirmed bool) {
	if c.opt.IssuerIdentity != nil && !(ek.identity != "" && c.opt.Contact != nil) {
		ek.identity = c.opt.IssuerIdentity(ek.issuer, ts)
		if ek.identity == "" {
			if c.opt.Contact != nil {
				return
			}
			ek.identity = ek.issuer
		}
	}
	if c.opt.Contact != nil {
		c.opt.Contact(ek.identity, ek.issuer, ek.dst, ek.proto, ek.port, ts, confirmed)
		return
	}
	history := c.edges[ek]
	history.add(ts)
	c.edges[ek] = history
}

// appendEdgeObservedTime updates a collector-owned, canonical timestamp slice
// in place. Collector edge slices are never shared until Edges or
// EdgesByFirstSeen copies them, so this avoids cloning and sorting the complete
// slice for every observed packet while preserving the same bounded selection:
// the true earliest timestamp plus the latest 127 timestamps.
func appendEdgeObservedTime(times []time.Time, ts time.Time) []time.Time {
	if ts.IsZero() {
		return times
	}

	utc := ts.UTC()
	insertAt := sort.Search(len(times), func(i int) bool {
		return !times[i].Before(utc)
	})
	if insertAt < len(times) && times[insertAt].Equal(utc) {
		return times
	}

	return insertDistinctTime(times, insertAt, utc)
}

// insertDistinctTime inserts at a known position in an owned sorted history.
// The caller has already checked for duplicates.
func insertDistinctTime[T any](times []T, insertAt int, value T) []T {
	if len(times) < maxEdgeObservedTimes {
		times = append(times, value)
		copy(times[insertAt+1:], times[insertAt:len(times)-1])
		times[insertAt] = value
		return times
	}

	if insertAt == 0 {
		// A new true earliest observation displaces the previous earliest;
		// the existing latest observations already occupy indexes 1..127.
		times[0] = value
		return times
	}
	if insertAt == 1 {
		// This timestamp is neither the true earliest nor one of the latest
		// 127 observations, so it does not belong in the bounded result.
		return times
	}

	// Drop the oldest non-earliest observation, shift only the affected
	// prefix, and insert the new timestamp at its resulting sorted position.
	copy(times[1:insertAt-1], times[2:insertAt])
	times[insertAt-1] = value
	return times
}

func (c *Collector) onTCP(srcIP, dstIP net.IP, tcp *layers.TCP, ts time.Time) {
	sport := uint16(tcp.SrcPort)
	dport := uint16(tcp.DstPort)
	if sport == 0 || dport == 0 {
		return
	}
	c.observeFTPPassiveControl(srcIP, dstIP, sport, dport, tcp.Payload, ts)

	if tcp.SYN && !tcp.ACK {
		if c.isExcludedPort(dport) {
			return
		}
		k := tcpKey{srcIP.String(), dstIP.String(), sport, dport, ""}
		if c.opt.Contact != nil {
			k.identity = c.opt.IssuerIdentity(k.cip, ts)
			if k.identity == "" {
				return
			}
		}
		if prev, ok := c.tcpSyn[k]; !ok || (c.opt.Contact != nil && ts.Sub(prev) > c.opt.PendingTTL) {
			c.tcpSyn[k] = ts
		}
		return
	}

	if tcp.SYN && tcp.ACK {
		if c.isExcludedPort(sport) {
			return
		}
		k := tcpKey{dstIP.String(), srcIP.String(), dport, sport, ""}
		if c.opt.Contact != nil {
			k.identity = c.opt.IssuerIdentity(k.cip, ts)
			if k.identity == "" {
				return
			}
		}
		synTS, ok := c.tcpSyn[k]
		if !ok {
			return
		}

		if c.opt.Contact != nil {
			delete(c.tcpSyn, k)
			if ts.Before(synTS) || ts.Sub(synTS) > c.opt.PendingTTL {
				return
			}
		}
		ek := edgeKey{identity: k.identity, issuer: k.cip, dst: k.sip, proto: ProtoTCP, port: k.spt}

		if c.opt.CollapseFTPPassive {
			if _, ok := c.ftpPassivePort[ek]; ok {
				return
			}
		}

		if c.opt.CollapseFTPPassive && ek.port >= c.opt.FTPPassiveMinPort {
			if _, ok := c.ftpControlSeen[pairKey{ek.identity, ek.issuer, ek.dst}]; ok {
				return
			}
		}

		if c.opt.CollapseFTPPassive && c.isFTPControlPort(ek.port) {
			c.ftpControlSeen[pairKey{ek.identity, ek.issuer, ek.dst}] = struct{}{}
		}

		// For SYN/SYN-ACK confirmed edges, observed time is the SYN timestamp.
		c.recordEdgeObservation(ek, synTS, true)
		return
	}

	//mid-session admission
	if tcp.RST {
		return
	}

	srcIsPrivate := isLocalIPv4(srcIP)
	dstIsPrivate := isLocalIPv4(dstIP)

	// Only private ↔ public
	if srcIsPrivate == dstIsPrivate {
		return
	}
	/*
		if srcIP.String() == "10.118.189.166" || dstIP.String() == "10.118.189.166" {
			fmt.Printf("IP observed: src: %s ; dst: %s\n", srcIP.String(), dstIP.String())
		}
	*/
	// Enforce "private is source"
	issuerIP := srcIP
	destIP := dstIP
	destPort := uint16(tcp.DstPort)
	//srcPort := uint16(tcp.SrcPort)

	if !srcIsPrivate && dstIsPrivate {
		issuerIP = dstIP
		destIP = srcIP
		destPort = uint16(tcp.SrcPort)
		//srcPort = uint16(tcp.DstPort)
	}

	ek := edgeKey{
		issuer: issuerIP.String(),
		dst:    destIP.String(),
		proto:  ProtoTCP,
		port:   destPort,
	}

	if c.opt.Contact != nil {
		ek.identity = c.opt.IssuerIdentity(ek.issuer, ts)
		if ek.identity == "" || c.isExcludedPort(destPort) {
			return
		}
	}
	if c.opt.CollapseFTPPassive {
		if _, ok := c.ftpPassivePort[ek]; ok {
			return
		}
	}

	if c.opt.CollapseFTPPassive && ek.port >= c.opt.FTPPassiveMinPort {
		if _, ok := c.ftpControlSeen[pairKey{ek.identity, ek.issuer, ek.dst}]; ok {
			return
		}
	}

	if c.opt.CollapseFTPPassive && c.isFTPControlPort(ek.port) {
		c.ftpControlSeen[pairKey{ek.identity, ek.issuer, ek.dst}] = struct{}{}
	}

	c.recordEdgeObservation(ek, ts, false)

}

func (c *Collector) onUDP(srcIP, dstIP net.IP, udp *layers.UDP, ts time.Time) {
	sport := uint16(udp.SrcPort)
	dport := uint16(udp.DstPort)
	if sport == 0 || dport == 0 {
		return
	}
	// Symmetric exclusion for UDP: if either side uses an excluded service port
	// (e.g. 53/123), suppress the flow regardless of capture order.
	if c.isExcludedPort(sport) || c.isExcludedPort(dport) {
		return
	}

	k := udpKey{cip: srcIP.String(), sip: dstIP.String(), cpt: sport, spt: dport}
	rev := udpKey{cip: k.sip, sip: k.cip, cpt: dport, spt: sport}
	if c.opt.Contact != nil {
		resolve := c.opt.IssuerIdentity
		if resolve(k.cip, ts) == "" && resolve(k.sip, ts) == "" {
			return
		}
		if first, ok := c.udpFirst[rev]; ok {
			delete(c.udpFirst, rev)
			issuer, dst, port := rev.cip, rev.sip, rev.spt
			id := resolve(issuer, first)
			if id == "" {
				issuer, dst, port = rev.sip, rev.cip, rev.cpt
				id = resolve(issuer, first)
			}
			if id != "" && id == resolve(issuer, ts) && !ts.Before(first) && ts.Sub(first) <= c.opt.PendingTTL {
				c.opt.Contact(id, issuer, dst, ProtoUDP, port, first, true)
				return
			}
		}
		if prev, pending := c.udpFirst[k]; !pending || ts.Sub(prev) > c.opt.PendingTTL {
			c.udpFirst[k] = ts
		}
		return
	}
	if _, ok := c.udpFirst[k]; !ok {
		c.udpFirst[k] = ts
	}

	revTS, ok := c.udpFirst[rev]
	if !ok {
		return
	}

	issuer := rev.cip
	dst := rev.sip
	port := rev.spt

	if c.opt.EnforcePrivateAsSource {
		issuerLocal := isLocalIPv4(net.ParseIP(issuer))
		dstLocal := isLocalIPv4(net.ParseIP(dst))
		if issuerLocal != dstLocal && dstLocal {
			issuer, dst = dst, issuer
			port = rev.cpt
		}
	}

	ek := edgeKey{issuer: issuer, dst: dst, proto: ProtoUDP, port: port}
	// For UDP confirmed edges, keep the first packet timestamp from issuer->dst flow.
	c.recordEdgeObservation(ek, revTS, true)
}

func (c *Collector) sweep(now time.Time) {
	cut := now.Add(-c.opt.PendingTTL)
	for k, t := range c.tcpSyn {
		if t.Before(cut) {
			delete(c.tcpSyn, k)
		}
	}
	for k, t := range c.udpFirst {
		if t.Before(cut) {
			delete(c.udpFirst, k)
		}
	}
	for k, t := range c.ftpPassivePend {
		if t.Before(cut) {
			delete(c.ftpPassivePend, k)
		}
	}
	for k, t := range c.ftpPassivePort {
		if t.Before(cut) {
			delete(c.ftpPassivePort, k)
		}
	}
}

// PassiveTCP checks previously advertised data ports before a ClientHello is
// admitted independently of transport handshake state.
func (c *Collector) PassiveTCP(device string, wire, dst netip.Addr, port uint16) bool {
	if len(c.ftpPassivePort) == 0 {
		return false
	}
	_, ok := c.ftpPassivePort[edgeKey{identity: device, issuer: wire.String(), dst: dst.String(), proto: ProtoTCP, port: port}]
	return ok
}

func (c *Collector) observeFTPPassiveControl(srcIP, dstIP net.IP, sport, dport uint16, payload []byte, ts time.Time) {
	if !c.opt.CollapseFTPPassive || len(payload) == 0 {
		return
	}

	if !c.isFTPControlPort(sport) && !c.isFTPControlPort(dport) {
		return
	}
	issuer := srcIP.String()
	dst := dstIP.String()
	if c.isFTPControlPort(dport) {
		if isFTPPassiveCommand(payload) {
			pair := pairKey{issuer: issuer, dst: dst}
			if c.opt.Contact != nil {
				pair.identity = c.opt.IssuerIdentity(issuer, ts)
				if pair.identity == "" {
					return
				}
			}
			c.ftpPassivePend[pair] = ts
		}
		return
	}

	port, ok := parseFTPPassiveReplyPort(payload)
	if !ok {
		return
	}

	pair := pairKey{issuer: dst, dst: issuer}
	if c.opt.Contact != nil {
		pair.identity = c.opt.IssuerIdentity(dst, ts)
		if pair.identity == "" {
			return
		}
	}
	if _, pending := c.ftpPassivePend[pair]; pending {
		delete(c.ftpPassivePend, pair)
	}
	c.ftpPassivePort[edgeKey{
		identity: pair.identity, issuer: pair.issuer,
		dst:   pair.dst,
		proto: ProtoTCP,
		port:  port,
	}] = ts
}

func isFTPPassiveCommand(payload []byte) bool {
	line := strings.ToUpper(strings.TrimSpace(string(payload)))
	return strings.HasPrefix(line, "PASV") || strings.HasPrefix(line, "EPSV")
}

func parseFTPPassiveReplyPort(payload []byte) (uint16, bool) {
	line := strings.TrimSpace(string(payload))
	if line == "" {
		return 0, false
	}
	upper := strings.ToUpper(line)
	switch {
	case strings.HasPrefix(upper, "227"):
		return parseFTP227PassivePort(line)
	case strings.HasPrefix(upper, "229"):
		return parseFTP229PassivePort(line)
	default:
		return 0, false
	}
}

func parseFTP227PassivePort(line string) (uint16, bool) {
	start := strings.IndexByte(line, '(')
	if start < 0 {
		return 0, false
	}
	end := strings.IndexByte(line[start+1:], ')')
	segment := line[start+1:]
	if end >= 0 {
		segment = line[start+1 : start+1+end]
	}
	parts := strings.Split(segment, ",")
	if len(parts) < 6 {
		return 0, false
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(parts[len(parts)-2]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(parts[len(parts)-1]))
	if err1 != nil || err2 != nil || p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 {
		return 0, false
	}
	port := p1*256 + p2
	if port <= 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}

func parseFTP229PassivePort(line string) (uint16, bool) {
	start := strings.IndexByte(line, '(')
	if start < 0 {
		return 0, false
	}
	end := strings.IndexByte(line[start+1:], ')')
	segment := line[start+1:]
	if end >= 0 {
		segment = line[start+1 : start+1+end]
	}
	fields := strings.FieldsFunc(segment, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if len(fields) == 0 {
		return 0, false
	}
	port, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}

func (c *Collector) isExcludedPort(port uint16) bool {
	if port == 0 || c.opt.ExcludedDstPorts == nil {
		return false
	}
	_, ok := c.opt.ExcludedDstPorts[port]
	return ok
}

func (c *Collector) isFTPControlPort(port uint16) bool {
	_, ok := c.opt.FTPControlPorts[port]
	return ok
}

func isLocalIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
		return true
	default:
		return false
	}
}
