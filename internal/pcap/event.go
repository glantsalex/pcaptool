// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"net"
	"time"
)

// EventType distinguishes what we extracted from the packet.
type EventType int

const (
	EventDNSQuery EventType = iota
	EventDNSResponse
	EventConnection
)

// Event is a normalized view of what we care about per packet.
type Event struct {
	Timestamp time.Time
	Type      EventType

	// Common layer 3/4 info
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   string // "tcp" or "udp" (for now)

	// DNS-related
	DNSID       uint16
	DNSQName    string
	DNSQTypeA   bool
	DNSIsReply  bool
	DNSAAnswers []net.IP // A records, only for responses (can be empty)
}
