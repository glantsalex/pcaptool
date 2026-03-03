// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import "strings"

// LooksLikeResolvableDNSName is a conservative filter used for "inferred from connectivity"
// backfill when DNS answers are missing due to snaplen truncation.
//
// We intentionally reject things that are often not real DNS hostnames in your data:
// - localhost
// - *.local
// - names without a dot
// - names containing underscores (common in device IDs / app tokens)
func LooksLikeResolvableDNSName(name string) bool {
	n := strings.TrimSpace(strings.TrimSuffix(name, "."))
	if n == "" {
		return false
	}
	l := strings.ToLower(n)

	if l == "localhost" {
		return false
	}
	if strings.HasSuffix(l, ".lan") {
		return false
	}
	if strings.HasSuffix(l, ".local") {
		return false
	}
	if !strings.Contains(l, ".") {
		return false
	}
	if strings.Contains(l, "_") {
		return false
	}

	return true
}
