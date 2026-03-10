// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package connectivity

import (
	"net"
	"sort"
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
	IssuerIP  string
	DstIP     string
	Protocol  L4Proto
	Port      uint16
	FirstSeen time.Time
}

type Options struct {
	PendingTTL             time.Duration
	SweepEvery             time.Duration
	ExcludedDstPorts       map[uint16]struct{}
	CollapseFTPPassive     bool
	FTPPassiveMinPort      uint16
	EnforcePrivateAsSource bool
}

func DefaultOptions() Options {
	return Options{
		PendingTTL:         30 * time.Second,
		SweepEvery:         2 * time.Second,
		CollapseFTPPassive: true,
		FTPPassiveMinPort:  30000,
	}
}

type pairKey struct {
	issuer string
	dst    string
}

type Collector struct {
	opt Options

	tcpSyn   map[tcpKey]time.Time
	udpFirst map[udpKey]time.Time

	edges map[edgeKey]time.Time

	lastSweep time.Time

	ftpControlSeen map[pairKey]struct{}
}

type tcpKey struct {
	cip string
	sip string
	cpt uint16
	spt uint16
}

type udpKey = tcpKey

type edgeKey struct {
	issuer string
	dst    string
	proto  L4Proto
	port   uint16
}

func NewCollector(opt Options) *Collector {
	if opt.PendingTTL <= 0 {
		opt.PendingTTL = DefaultOptions().PendingTTL
	}
	if opt.SweepEvery <= 0 {
		opt.SweepEvery = DefaultOptions().SweepEvery
	}
	if opt.FTPPassiveMinPort == 0 {
		opt.FTPPassiveMinPort = DefaultOptions().FTPPassiveMinPort
	}
	return &Collector{
		opt:            opt,
		tcpSyn:         make(map[tcpKey]time.Time, 8192),
		udpFirst:       make(map[udpKey]time.Time, 8192),
		edges:          make(map[edgeKey]time.Time, 32768),
		ftpControlSeen: make(map[pairKey]struct{}, 1024),
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
	for k, ts := range c.edges {
		out = append(out, Edge{
			IssuerIP:  k.issuer,
			DstIP:     k.dst,
			Protocol:  k.proto,
			Port:      k.port,
			FirstSeen: ts,
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
		return out[i].Port < out[j].Port
	})

	return out
}

func (c *Collector) EdgesByFirstSeen() []Edge {
	out := make([]Edge, 0, len(c.edges))
	for k, ts := range c.edges {
		out = append(out, Edge{
			IssuerIP:  k.issuer,
			DstIP:     k.dst,
			Protocol:  k.proto,
			Port:      k.port,
			FirstSeen: ts,
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
		return out[i].Port < out[j].Port
	})

	return out
}

func (c *Collector) onTCP(srcIP, dstIP net.IP, tcp *layers.TCP, ts time.Time) {
	sport := uint16(tcp.SrcPort)
	dport := uint16(tcp.DstPort)
	if sport == 0 || dport == 0 {
		return
	}

	if tcp.SYN && !tcp.ACK {
		if c.isExcludedPort(dport) {
			return
		}
		k := tcpKey{srcIP.String(), dstIP.String(), sport, dport}
		if _, ok := c.tcpSyn[k]; !ok {
			c.tcpSyn[k] = ts
		}
		return
	}

	if tcp.SYN && tcp.ACK {
		if c.isExcludedPort(sport) {
			return
		}
		k := tcpKey{dstIP.String(), srcIP.String(), dport, sport}
		synTS, ok := c.tcpSyn[k]
		if !ok {
			return
		}

		ek := edgeKey{k.cip, k.sip, ProtoTCP, k.spt}

		if c.opt.CollapseFTPPassive && ek.port >= c.opt.FTPPassiveMinPort {
			if _, ok := c.ftpControlSeen[pairKey{ek.issuer, ek.dst}]; ok {
				return
			}
		}

		if c.opt.CollapseFTPPassive && (ek.port == 21 || ek.port == 990) {
			c.ftpControlSeen[pairKey{ek.issuer, ek.dst}] = struct{}{}
		}

		// For SYN/SYN-ACK confirmed edges, observed time is the SYN timestamp.
		if prev, ok := c.edges[ek]; !ok || synTS.Before(prev) {
			c.edges[ek] = synTS
		}
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

	if c.opt.CollapseFTPPassive && ek.port >= c.opt.FTPPassiveMinPort {
		if _, ok := c.ftpControlSeen[pairKey{ek.issuer, ek.dst}]; ok {
			return
		}
	}

	if c.opt.CollapseFTPPassive && (ek.port == 21 || ek.port == 990) {
		c.ftpControlSeen[pairKey{ek.issuer, ek.dst}] = struct{}{}
	}

	if prev, ok := c.edges[ek]; !ok || ts.Before(prev) {
		c.edges[ek] = ts
	}

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

	k := udpKey{srcIP.String(), dstIP.String(), sport, dport}
	if _, ok := c.udpFirst[k]; !ok {
		c.udpFirst[k] = ts
	}

	rev := udpKey{dstIP.String(), srcIP.String(), dport, sport}
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

	ek := edgeKey{issuer, dst, ProtoUDP, port}
	// For UDP confirmed edges, keep the first packet timestamp from issuer->dst flow.
	if prev, ok := c.edges[ek]; !ok || revTS.Before(prev) {
		c.edges[ek] = revTS
	}
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
}

func (c *Collector) isExcludedPort(port uint16) bool {
	if port == 0 || c.opt.ExcludedDstPorts == nil {
		return false
	}
	_, ok := c.opt.ExcludedDstPorts[port]
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
