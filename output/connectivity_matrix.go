// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
)

// WriteNetworkTopologyMatrix prints a topology matrix grouped by issuer.
// Unique row key is: Issuer | Destination IP | DNS Name | Protocol | Port.
func WriteNetworkTopologyMatrix(w io.Writer, entries []dns.TopologyEntry) error {
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "No network topology entries found.")
		return err
	}

	const (
		hIssuer = "Issuer IP"
		hDstIP  = "Destination IP"
		hDNS    = "DNS Name"
		hSource = "Source"
		hProto  = "Protocol"
		hPort   = "Port"
	)

	issuerWidth := len(hIssuer)
	dstWidth := len(hDstIP)
	dnsWidth := len(hDNS)
	sourceWidth := len(hSource)
	protoWidth := len(hProto)
	portWidth := len(hPort)

	for _, e := range entries {
		if l := len(e.IssuerIP); l > issuerWidth {
			issuerWidth = l
		}
		if l := len(e.DestinationIP); l > dstWidth {
			dstWidth = l
		}
		if l := len(e.DNSName); l > dnsWidth {
			dnsWidth = l
		}
		if l := len(e.DNSSource); l > sourceWidth {
			sourceWidth = l
		}
		if l := len(e.Protocol); l > protoWidth {
			protoWidth = l
		}
		if l := len(fmt.Sprintf("%d", e.Port)); l > portWidth {
			portWidth = l
		}
	}

	sep := func(n int) string { return strings.Repeat("-", n) }

	fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		issuerWidth, hIssuer,
		dstWidth, hDstIP,
		dnsWidth, hDNS,
		sourceWidth, hSource,
		protoWidth, hProto,
		portWidth, hPort,
	)
	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
		sep(issuerWidth), sep(dstWidth), sep(dnsWidth),
		sep(sourceWidth), sep(protoWidth), sep(portWidth))

	currentIssuer := ""
	for idx, e := range entries {
		issuerCol := ""
		if idx == 0 || e.IssuerIP != currentIssuer {
			if idx > 0 {
				fmt.Fprintln(w)
			}
			currentIssuer = e.IssuerIP
			issuerCol = e.IssuerIP
		}

		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %-*s  %-*d\n",
			issuerWidth, issuerCol,
			dstWidth, e.DestinationIP,
			dnsWidth, e.DNSName,
			sourceWidth, e.DNSSource,
			protoWidth, e.Protocol,
			portWidth, e.Port,
		)
	}

	fmt.Fprintf(w, "\n%s  %s  %s  %s  %s  %s\n",
		sep(issuerWidth), sep(dstWidth), sep(dnsWidth),
		sep(sourceWidth), sep(protoWidth), sep(portWidth))

	return nil
}

type networkTopologyMatrixJSON struct {
	Version int                              `json:"version"`
	Entries []networkTopologyMatrixJSONEntry `json:"entries"`
}

type networkTopologyMatrixJSONEntry struct {
	IssuerIP      string `json:"issuer_ip"`
	DestinationIP string `json:"destination_ip"`
	DNSName       string `json:"dns_name"`
	DNSSource     string `json:"dns_source"`
	Protocol      string `json:"protocol"`
	Port          uint16 `json:"port"`
	ObservedAtUTC string `json:"observed_at_utc,omitempty"`
}

// WriteNetworkTopologyMatrixJSON writes the topology matrix in machine-readable JSON.
func WriteNetworkTopologyMatrixJSON(w io.Writer, entries []dns.TopologyEntry) error {
	payload := networkTopologyMatrixJSON{
		Version: 1,
		Entries: make([]networkTopologyMatrixJSONEntry, 0, len(entries)),
	}
	for _, entry := range entries {
		row := networkTopologyMatrixJSONEntry{
			IssuerIP:      entry.IssuerIP,
			DestinationIP: entry.DestinationIP,
			DNSName:       entry.DNSName,
			DNSSource:     entry.DNSSource,
			Protocol:      entry.Protocol,
			Port:          entry.Port,
		}
		if !entry.ObservedAt.IsZero() {
			row.ObservedAtUTC = entry.ObservedAt.UTC().Format(time.RFC3339Nano)
		}
		payload.Entries = append(payload.Entries, row)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// WriteTCPEgressEndpoints writes unique public destination IPs with protocol port lists.
// Output format (compressed):
//
//	IP[,dns:[d1;d2...]][,tcp:[p1;p2...]][,udp:[p1;p2...]]
//
// Empty sections are omitted completely.
// Example: 2.16.153.198,tcp:[443]
func WriteTCPEgressEndpoints(w io.Writer, entries []dns.TopologyEntry) error {
	type agg struct {
		dns map[string]struct{}
		tcp map[uint16]struct{}
		udp map[uint16]struct{}
	}

	m := make(map[string]*agg, len(entries))

	for _, e := range entries {
		ip := net.ParseIP(e.DestinationIP)
		if ip == nil || ip.To4() == nil || isLocalIPv4(ip) {
			continue
		}

		a := m[e.DestinationIP]
		if a == nil {
			a = &agg{
				dns: make(map[string]struct{}),
				tcp: make(map[uint16]struct{}),
				udp: make(map[uint16]struct{}),
			}
			m[e.DestinationIP] = a
		}

		if e.DNSName != "" {
			a.dns[e.DNSName] = struct{}{}
		}

		switch e.Protocol {
		case "tcp":
			a.tcp[e.Port] = struct{}{}
		case "udp":
			a.udp[e.Port] = struct{}{}
		}
	}

	if len(m) == 0 {
		_, err := fmt.Fprintln(w, "No public egress endpoints found.")
		return err
	}

	ips := make([]string, 0, len(m))
	for ip := range m {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ip := range ips {
		a := m[ip]

		dnsList := make([]string, 0, len(a.dns))
		for d := range a.dns {
			dnsList = append(dnsList, d)
		}
		sort.Strings(dnsList)

		tcpList := make([]uint16, 0, len(a.tcp))
		for p := range a.tcp {
			tcpList = append(tcpList, p)
		}
		sort.Slice(tcpList, func(i, j int) bool { return tcpList[i] < tcpList[j] })

		udpList := make([]uint16, 0, len(a.udp))
		for p := range a.udp {
			udpList = append(udpList, p)
		}
		sort.Slice(udpList, func(i, j int) bool { return udpList[i] < udpList[j] })

		// Build compressed parts.
		parts := make([]string, 0, 4)
		parts = append(parts, ip)

		if len(dnsList) > 0 {
			parts = append(parts, "dns:["+joinStrings(dnsList)+"]")
		}
		if len(tcpList) > 0 {
			parts = append(parts, "tcp:["+joinPorts(tcpList)+"]")
		}
		if len(udpList) > 0 {
			parts = append(parts, "udp:["+joinPorts(udpList)+"]")
		}

		fmt.Fprintln(w, strings.Join(parts, ","))
	}

	return nil
}

func joinStrings(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return strings.Join(v, ";")
}

func joinPorts(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	out := make([]string, 0, len(v))
	for _, p := range v {
		out = append(out, fmt.Sprintf("%d", p))
	}
	return strings.Join(out, ";")
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
