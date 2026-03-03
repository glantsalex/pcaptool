// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strconv"
	"strings"
)

// parsePortSet parses comma-separated ports like "53,123" into a set.
// Empty string => empty set.
// Returns error on non-numeric or out-of-range ports.
func parsePortSet(s string) (map[uint16]struct{}, error) {
	out := make(map[uint16]struct{})
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}

	parts := strings.SplitSeq(s, ",")
	for p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port out of range %d (must be 1..65535)", n)
		}
		out[uint16(n)] = struct{}{}
	}
	return out, nil
}
