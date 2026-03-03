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

type tableRow struct {
	RequestTime string
	IssuerIP    string
	DNSName     string
	ResolvedIP  string
	Source      string
	ResolverIP  string
	DestPort    string
}

func WriteTable(w io.Writer, records []dns.OutputRecord) error {
	// Build flattened rows with stacked Resolved IPs
	rows := buildTableRows(records)

	// Column headers
	headers := []string{
		"Request Time",
		"Issuer IP",
		"DNS Name",
		"Resolved IP(s)",
		"Source",
		"Resolver IP",
		"Port",
	}

	// Compute widths based on headers and *all* rows
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for _, row := range rows {
		cells := []string{
			row.RequestTime,
			row.IssuerIP,
			row.DNSName,
			row.ResolvedIP,
			row.Source,
			row.ResolverIP,
			row.DestPort,
		}
		for i, c := range cells {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	// Helpers
	printRow := func(cells []string) {
		fmt.Fprint(w, "|")
		for i, c := range cells {
			fmt.Fprintf(w, " %-*s |", widths[i], c)
		}
		fmt.Fprintln(w)
	}

	printSep := func() {
		fmt.Fprint(w, "|")
		for _, width := range widths {
			fmt.Fprint(w, strings.Repeat("-", width+2), "|")
		}
		fmt.Fprintln(w)
	}

	// Header + separator
	printRow(headers)
	printSep()

	// Data rows
	for _, row := range rows {
		printRow([]string{
			row.RequestTime,
			row.IssuerIP,
			row.DNSName,
			row.ResolvedIP,
			row.Source,
			row.ResolverIP,
			row.DestPort,
		})
	}

	return nil
}

func buildTableRows(records []dns.OutputRecord) []tableRow {
	var rows []tableRow

	for _, r := range records {
		// Convert destination port and resolver to strings
		resolver := ""
		if r.ResolverIP != nil {
			resolver = *r.ResolverIP
		}
		destPort := ""
		if r.DestinationPort != nil {
			destPort = fmt.Sprintf("%d", *r.DestinationPort)
		}

		lookupSource := func(ip string) string {
			if r.ResolvedIPSources == nil {
				return ""
			}
			return r.ResolvedIPSources[ip]
		}

		// If no resolved IPs, still emit a single row (edge case)
		if len(r.ResolvedIPs) == 0 {
			rows = append(rows, tableRow{
				RequestTime: r.RequestTimeStr,
				IssuerIP:    r.IssuerIP,
				DNSName:     r.DNSName,
				ResolvedIP:  "",
				Source:      "",
				ResolverIP:  resolver,
				DestPort:    destPort,
			})
			continue
		}

		// First IP: print all columns
		rows = append(rows, tableRow{
			RequestTime: r.RequestTimeStr,
			IssuerIP:    r.IssuerIP,
			DNSName:     r.DNSName,
			ResolvedIP:  r.ResolvedIPs[0],
			Source:      lookupSource(r.ResolvedIPs[0]),
			ResolverIP:  resolver,
			DestPort:    destPort,
		})

		// Remaining IPs: stack under Resolved IP(s) column, other columns blank
		// BUT Source is per-IP, so we print it on each stacked line.
		for i := 1; i < len(r.ResolvedIPs); i++ {
			rows = append(rows, tableRow{
				RequestTime: "",
				IssuerIP:    "",
				DNSName:     "",
				ResolvedIP:  r.ResolvedIPs[i],
				Source:      lookupSource(r.ResolvedIPs[i]),
				ResolverIP:  "",
				DestPort:    "",
			})
		}
	}

	return rows
}

// WriteTableWithStats writes the main table and then a stats footer
// including a pretty-formatted table of DNS with no connections.
func WriteTableWithStats(w io.Writer, records []dns.OutputRecord, stats dns.TableStats) error {
	// 1) main table
	if err := WriteTable(w, records); err != nil {
		return err
	}

	fmt.Fprintln(w)

	// 2) basic stats
	fmt.Fprintln(w, "Stats:")
	fmt.Fprintf(w, "  Unique source IPs:        %d\n", stats.UniqueSources)
	fmt.Fprintf(w, "  Unique destination IPs:   %d\n", stats.UniqueDestIPs)
	fmt.Fprintf(w, "  Unique DNS with traffic:  %d\n", stats.UniqueConnectedDNS)
	fmt.Fprintln(w)

	return nil
}

// WriteUnresolvedDNSTable writes unresolved DNS rows:
// DNS Name | Issuer IP | First PCAP File where this unresolved DNS was seen.
func WriteUnresolvedDNSTable(w io.Writer, unresolved []dns.DNSUnresolvedStat) error {
	if len(unresolved) == 0 {
		_, err := fmt.Fprintln(w, "No unresolved DNS queries were found.")
		return err
	}

	const (
		nameHeader   = "DNS Name"
		issuerHeader = "Issuer IP"
		fileHeader   = "First PCAP File"
	)

	nameWidth := len(nameHeader)
	issuerWidth := len(issuerHeader)
	fileWidth := len(fileHeader)

	for _, u := range unresolved {
		if l := len(u.Name); l > nameWidth {
			nameWidth = l
		}
		if l := len(u.IssuerIP); l > issuerWidth {
			issuerWidth = l
		}
		if l := len(u.FirstPCAPFile); l > fileWidth {
			fileWidth = l
		}
	}

	printRow := func(a, b, c string) {
		fmt.Fprintf(w, "%-*s  %-*s  %-*s\n", nameWidth, a, issuerWidth, b, fileWidth, c)
	}

	sep := func(n int) string { return strings.Repeat("-", n) }

	printRow(nameHeader, issuerHeader, fileHeader)
	fmt.Fprintf(w, "%s  %s  %s\n", sep(nameWidth), sep(issuerWidth), sep(fileWidth))

	prevName := ""
	for _, u := range unresolved {
		nameCol := u.Name
		if nameCol == prevName {
			nameCol = ""
		} else {
			prevName = u.Name
		}
		printRow(nameCol, u.IssuerIP, u.FirstPCAPFile)
	}

	fmt.Fprintf(w, "%s  %s  %s\n", sep(nameWidth), sep(issuerWidth), sep(fileWidth))
	return nil
}
