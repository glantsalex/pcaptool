// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/aglants/pcaptool/internal/dns"
)

func WriteIssuerProfileTable(w io.Writer, prof []dns.IssuerProfile) error {
	if len(prof) == 0 {
		_, err := fmt.Fprintln(w, "No DNS issuer activity found.")
		return err
	}

	const (
		hIssuer = "Issuer IP"
		hDNS    = "Total DNS"
		hNames  = "Unique Domains"
		hIPs    = "Unique IPs"
		hPorts  = "Unique Ports"
		hRate   = "Connection Rate"
	)

	// Column widths
	wIssuer := len(hIssuer)
	wDNS := len(hDNS)
	wNames := len(hNames)
	wIPs := len(hIPs)
	wPorts := len(hPorts)
	wRate := len(hRate)

	for _, p := range prof {
		if len(p.IssuerIP) > wIssuer {
			wIssuer = len(p.IssuerIP)
		}
		if l := len(fmt.Sprintf("%d", p.TotalDNS)); l > wDNS {
			wDNS = l
		}
		if l := len(fmt.Sprintf("%d", p.UniqueNames)); l > wNames {
			wNames = l
		}
		if l := len(fmt.Sprintf("%d", p.UniqueIPs)); l > wIPs {
			wIPs = l
		}
		if l := len(fmt.Sprintf("%d", p.UniquePorts)); l > wPorts {
			wPorts = l
		}
		if l := len(fmt.Sprintf("%.2f", p.ConnectionRate)); l > wRate {
			wRate = l
		}
	}

	sep := func(n int) string { return strings.Repeat("-", n) }

	// Header
	fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
		wIssuer, hIssuer,
		wDNS, hDNS,
		wNames, hNames,
		wIPs, hIPs,
		wPorts, hPorts,
		wRate, hRate,
	)

	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
		sep(wIssuer), sep(wDNS), sep(wNames), sep(wIPs), sep(wPorts), sep(wRate))

	// Rows
	for _, p := range prof {
		fmt.Fprintf(w, "%-*s  %-*d  %-*d  %-*d  %-*d  %-*.2f\n",
			wIssuer, p.IssuerIP,
			wDNS, p.TotalDNS,
			wNames, p.UniqueNames,
			wIPs, p.UniqueIPs,
			wPorts, p.UniquePorts,
			wRate, p.ConnectionRate,
		)
	}

	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
		sep(wIssuer), sep(wDNS), sep(wNames), sep(wIPs), sep(wPorts), sep(wRate))

	return nil
}
