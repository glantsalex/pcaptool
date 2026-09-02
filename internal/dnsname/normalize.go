// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package dnsname provides shared DNS-name normalization helpers.
package dnsname

import "strings"

// Normalize returns name with surrounding whitespace removed, letters
// lowercased, and one trailing dot removed.
func Normalize(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".")
}
