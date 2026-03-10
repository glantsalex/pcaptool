// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type IPDNSPair struct {
	IP  string
	DNS string
}

// LoadIPToDNSFromFile loads an IP->[]DNS mapping from a simple text/CSV file.
//
// Supported line formats (auto-detected):
//   - dns,ip
//   - ip,dns
//   - dns ip
//   - ip dns
//
// Rules:
//   - IPv4 only
//   - ignores empty lines and comment lines (#...)
//   - trims whitespace, lowercases DNS, trims trailing dot.
//   - preserves "first seen" ordering per IP, de-dupes DNS per IP.
func LoadIPToDNSFromFile(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	out := make(map[string][]string, 4096)
	seen := make(map[string]map[string]struct{}, 4096)

	add := func(ip, dns string) {
		ip, ok := canonicalIPv4String(ip)
		if !ok {
			return
		}
		dns = canonicalDNSName(dns)

		if ip == "" || dns == "" {
			return
		}

		m := seen[ip]
		if m == nil {
			m = make(map[string]struct{}, 8)
			seen[ip] = m
		}
		if _, ok := m[dns]; ok {
			return
		}
		m[dns] = struct{}{}
		out[ip] = append(out[ip], dns)
	}

	splitLine := func(line string) []string {
		// try comma first
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				return []string{parts[0], parts[1]}
			}
		}
		// fallback to whitespace (tabs/spaces)
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			return []string{fields[0], fields[1]}
		}
		return nil
	}

	sc := bufio.NewScanner(f)
	// allow long lines (some people dump huge CSVs)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := splitLine(line)
		if len(parts) < 2 {
			continue
		}

		a := strings.TrimSpace(parts[0])
		b := strings.TrimSpace(parts[1])

		// Auto-detect which side is IP
		if ip, ok := canonicalIPv4String(a); ok {
			// ip,dns
			add(ip, b)
			continue
		}
		if ip, ok := canonicalIPv4String(b); ok {
			// dns,ip
			add(ip, a)
			continue
		}

		// neither side looks like an IPv4 => skip
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %q: %w", path, err)
	}

	return out, nil
}

func MergeIPToDNSMaps(base, extra map[string][]string) (map[string][]string, []IPDNSPair) {
	out := make(map[string][]string, len(base))
	seen := make(map[string]map[string]struct{}, len(base))
	baseHasIP := make(map[string]struct{}, len(base))

	add := func(ip, dns string, trackNew bool, newPairs *[]IPDNSPair) {
		ip, ok := canonicalIPv4String(ip)
		if !ok {
			return
		}
		dns = canonicalDNSName(dns)
		if dns == "" {
			return
		}
		m := seen[ip]
		if m == nil {
			m = make(map[string]struct{}, 8)
			seen[ip] = m
		}
		if _, ok := m[dns]; ok {
			return
		}
		m[dns] = struct{}{}
		out[ip] = append(out[ip], dns)
		if trackNew && newPairs != nil {
			*newPairs = append(*newPairs, IPDNSPair{IP: ip, DNS: dns})
		}
	}

	for ip, names := range base {
		for _, dns := range names {
			add(ip, dns, false, nil)
		}
	}
	for ip := range out {
		baseHasIP[ip] = struct{}{}
	}

	newPairs := make([]IPDNSPair, 0, 128)
	for ip, names := range extra {
		canonIP, ok := canonicalIPv4String(ip)
		if !ok {
			continue
		}
		// Conservative persistence: do not add learned names for IPs already
		// present in base CSV. Learn only previously unseen IPs.
		if _, exists := baseHasIP[canonIP]; exists {
			continue
		}

		// One CSV row per IP: choose a deterministic representative DNS
		// from learned candidates (shortest FQDN, then lexical).
		best := ""
		seenLocal := make(map[string]struct{}, len(names))
		for _, dns := range names {
			dns = canonicalDNSName(dns)
			if dns == "" {
				continue
			}
			if _, ok := seenLocal[dns]; ok {
				continue
			}
			seenLocal[dns] = struct{}{}
			if best == "" || len(dns) < len(best) || (len(dns) == len(best) && dns < best) {
				best = dns
			}
		}
		if best != "" {
			add(canonIP, best, true, &newPairs)
		}
	}

	sort.Slice(newPairs, func(i, j int) bool {
		if newPairs[i].IP != newPairs[j].IP {
			return newPairs[i].IP < newPairs[j].IP
		}
		return newPairs[i].DNS < newPairs[j].DNS
	})

	return out, newPairs
}

// StrongObservedIPDNSPairsFromTransactions extracts IP->DNS pairs that have
// direct DNS-answer-backed and observed-connection-backed evidence.
//
// Effective source class:
// - dns+synack
//
// Private destination IPv4s are excluded because topology fallback never attributes
// private destinations from CSV anyway.
func StrongObservedIPDNSPairsFromTransactions(txs []*DNSTransaction) map[string][]string {
	out := make(map[string][]string, 1024)
	seen := make(map[string]map[string]struct{}, 1024)

	add := func(ip, dns string) {
		ip, ok := canonicalIPv4String(ip)
		if !ok {
			return
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsPrivate() {
			return
		}
		dns = canonicalDNSName(dns)
		if dns == "" {
			return
		}
		m := seen[ip]
		if m == nil {
			m = make(map[string]struct{}, 8)
			seen[ip] = m
		}
		if _, ok := m[dns]; ok {
			return
		}
		m[dns] = struct{}{}
		out[ip] = append(out[ip], dns)
	}

	for _, tx := range txs {
		if tx == nil || tx.DNSName == "" || len(tx.ResolvedIPs) == 0 {
			continue
		}
		for _, ip := range tx.ResolvedIPs {
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			ipStr := ip4.String()

			ev := EvNone
			if tx.ResolvedIPEvidence != nil {
				ev = tx.ResolvedIPEvidence[ipStr]
			}
			if ev == EvNone {
				ev = tx.NameEvidence
			}

			if ev&(EvDNSAnswer|EvObservedConn) != (EvDNSAnswer | EvObservedConn) {
				continue
			}
			// Do not persist connectivity-backfilled IPs into the learned CSV.
			// They are useful as transient attribution hints, but not as durable
			// DNS truth because the IP was not directly parsed from the answer.
			if ev&EvConnInferred != 0 {
				continue
			}
			add(ipStr, tx.DNSName)
		}
	}

	return out
}

func AppendIPDNSPairsToFile(path string, pairs []IPDNSPair) error {
	if len(pairs) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for %q: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open %q for append: %w", path, err)
	}
	defer f.Close()

	needsLeadingNewline := false
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		if _, err := f.Seek(-1, io.SeekEnd); err == nil {
			var b [1]byte
			if _, err := f.Read(b[:]); err == nil && b[0] != '\n' {
				needsLeadingNewline = true
			}
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek append end %q: %w", path, err)
	}

	w := bufio.NewWriter(f)
	if needsLeadingNewline {
		if _, err := w.WriteString("\n"); err != nil {
			return fmt.Errorf("write newline %q: %w", path, err)
		}
	}
	for _, p := range pairs {
		if p.IP == "" || p.DNS == "" {
			continue
		}
		// Keep existing file convention: dns,ip
		if _, err := fmt.Fprintf(w, "%s,%s\n", p.DNS, p.IP); err != nil {
			return fmt.Errorf("append pair to %q: %w", path, err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush %q: %w", path, err)
	}
	return nil
}

func canonicalIPv4String(s string) (string, bool) {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	return ip4.String(), true
}
