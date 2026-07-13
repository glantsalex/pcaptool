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

func ensurePortExcluded(ports map[uint16]struct{}, port uint16) map[uint16]struct{} {
	if ports == nil {
		ports = make(map[uint16]struct{}, 1)
	}
	if port != 0 {
		ports[port] = struct{}{}
	}
	return ports
}

func parseStrictPortSet(s string) (map[uint16]struct{}, error) {
	out := make(map[uint16]struct{})
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("invalid port entry 1 value %q: must not be empty", s)
	}

	for i, raw := range strings.Split(s, ",") {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("invalid port entry %d value %q: must not be empty", i+1, raw)
		}

		n, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("invalid port entry %d value %q: must be numeric", i+1, value)
		}
		if n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port entry %d value %q: must be 1..65535", i+1, value)
		}
		out[uint16(n)] = struct{}{}
	}
	return out, nil
}

func parseOptionalPortRangeSet(s string) (map[uint16]struct{}, error) {
	out := make(map[uint16]struct{})
	if strings.TrimSpace(s) == "" {
		return out, nil
	}

	for i, raw := range strings.Split(s, ",") {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("invalid port range entry %d value %q: must not be empty", i+1, raw)
		}

		bounds := strings.Split(value, "-")
		switch len(bounds) {
		case 1:
			port, err := parseStrictPort(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range entry %d value %q: %w", i+1, value, err)
			}
			out[port] = struct{}{}
		case 2:
			start, err := parseStrictPort(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range entry %d value %q start: %w", i+1, value, err)
			}
			end, err := parseStrictPort(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range entry %d value %q end: %w", i+1, value, err)
			}
			if start > end {
				return nil, fmt.Errorf(
					"invalid port range entry %d value %q: range start %d exceeds end %d",
					i+1,
					value,
					start,
					end,
				)
			}
			for port := int(start); port <= int(end); port++ {
				out[uint16(port)] = struct{}{}
			}
		default:
			return nil, fmt.Errorf(
				"invalid port range entry %d value %q: must be a port or inclusive start-end range",
				i+1,
				value,
			)
		}
	}
	return out, nil
}

func parseStrictPort(s string) (uint16, error) {
	value := strings.TrimSpace(s)
	if value == "" {
		return 0, fmt.Errorf("invalid port value %q: must not be empty", s)
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid port value %q: must be numeric", value)
	}
	if n <= 0 || n > 65535 {
		return 0, fmt.Errorf("invalid port value %q: must be 1..65535", value)
	}
	return uint16(n), nil
}
