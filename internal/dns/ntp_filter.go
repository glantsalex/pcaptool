// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import "strings"

// LooksLikeNTPDNSName returns true when a DNS name likely targets an NTP/time-sync service.
//
// This is heuristic by design. It intentionally catches common NTP naming patterns such as:
// - time.*
// - ntp.*
// - *.pool.ntp.org
// - labels like ntp, ntp1, ntp-foo, time, time1, timesync
func LooksLikeNTPDNSName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
	if n == "" {
		return false
	}

	if strings.HasPrefix(n, "time.") || strings.Contains(n, ".time.") {
		return true
	}
	if strings.HasPrefix(n, "ntp.") || strings.Contains(n, ".ntp.") || strings.HasSuffix(n, ".ntp") {
		return true
	}
	if n == "pool.ntp.org" || strings.HasSuffix(n, ".pool.ntp.org") {
		return true
	}

	labels := strings.Split(n, ".")
	for _, lbl := range labels {
		switch lbl {
		case "ntp", "time", "timesync", "sntp", "ntpd", "chrony", "chronyd":
			return true
		}
		if looksLikeIndexedPrefix(lbl, "ntp") ||
			looksLikeIndexedPrefix(lbl, "time") ||
			looksLikeIndexedPrefix(lbl, "timesync") {
			return true
		}
	}

	// Extra token checks for forms like "foo-timesync-bar.example.com".
	if strings.Contains(n, "timesync") || strings.Contains(n, "chrony") {
		return true
	}

	return false
}

// FilterOutNTPDNSTransactions removes DNS transactions whose names look NTP-related.
// Synthetic SNI transactions are kept even when their names match these patterns.
func FilterOutNTPDNSTransactions(txs []*DNSTransaction) ([]*DNSTransaction, int) {
	if len(txs) == 0 {
		return txs, 0
	}

	out := make([]*DNSTransaction, 0, len(txs))
	dropped := 0

	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if tx.NameEvidence&EvSNI != 0 {
			out = append(out, tx)
			continue
		}
		if LooksLikeNTPDNSName(tx.DNSName) {
			dropped++
			continue
		}
		out = append(out, tx)
	}

	return out, dropped
}

func looksLikeIndexedPrefix(label, prefix string) bool {
	if !strings.HasPrefix(label, prefix) {
		return false
	}
	rest := label[len(prefix):]
	if rest == "" {
		return true
	}
	if strings.HasPrefix(rest, "-") {
		return len(rest) > 1
	}
	return allDigits(rest)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
