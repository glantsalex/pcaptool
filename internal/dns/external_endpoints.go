// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// ExternalEndpoint represents one aggregated service entry.
type ExternalEndpoint struct {
	DNSSuffix    string
	DNSNames     map[string]struct{}
	IPs          map[string]struct{}
	PortsByProto map[string]map[uint16]struct{}
}

// BuildExternalEndpoints aggregates topology entries by dns_suffix.
func BuildExternalEndpoints(entries []TopologyEntry) []*ExternalEndpoint {
	bySuffix := make(map[string]*ExternalEndpoint)

	for _, e := range entries {
		if e.DNSName == "" {
			continue
		}

		suffix := dnsSuffix(e.DNSName)
		if suffix == "" {
			continue
		}

		ep := bySuffix[suffix]
		if ep == nil {
			ep = &ExternalEndpoint{
				DNSSuffix:    suffix,
				DNSNames:     make(map[string]struct{}),
				IPs:          make(map[string]struct{}),
				PortsByProto: make(map[string]map[uint16]struct{}),
			}
			bySuffix[suffix] = ep
		}

		ep.DNSNames[e.DNSName] = struct{}{}
		ep.IPs[e.DestinationIP] = struct{}{}

		if e.Protocol != "" && e.Port != 0 {
			pm := ep.PortsByProto[e.Protocol]
			if pm == nil {
				pm = make(map[uint16]struct{})
				ep.PortsByProto[e.Protocol] = pm
			}
			pm[e.Port] = struct{}{}
		}
	}

	out := make([]*ExternalEndpoint, 0, len(bySuffix))
	for _, ep := range bySuffix {
		out = append(out, ep)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].DNSSuffix < out[j].DNSSuffix
	})

	return out
}

// WriteExternalEndpoints emits external-endpoints.txt.
func WriteExternalEndpoints(w io.Writer, eps []*ExternalEndpoint) error {
	// Track global unique ports
	globalPorts := map[string]map[uint16]struct{}{
		"tcp": {},
		"udp": {},
	}

	for _, ep := range eps {
		fmt.Fprintf(w, "- id: \"svc_%s\"\n", ep.DNSSuffix)
		fmt.Fprintf(w, "  group: \"%s\"\n", ep.DNSSuffix)
		fmt.Fprintf(w, "  match: { dns_suffix: \"%s\" }\n", ep.DNSSuffix)
		fmt.Fprintf(w, "  listeners:\n")

		protos := sortedKeysU16(ep.PortsByProto)
		for _, proto := range protos {
			ports := sortedU16(ep.PortsByProto[proto])
			for _, p := range ports {
				globalPorts[proto][p] = struct{}{}
			}
			fmt.Fprintf(w, "    - { proto: \"%s\", port: [%s] }\n",
				proto, joinU16(ports))
		}

		fmt.Fprintf(w, "  ip_churn_expected: true\n")
		fmt.Fprintf(w, "  grouping_key: [\"dns_suffix\", \"proto\", \"dst_port\"]\n")
		fmt.Fprintf(w, "  observations:\n")

		fmt.Fprintf(w, "    top_dns_seen: [%s]\n",
			joinStrings(sortedStrings(ep.DNSNames)))

		fmt.Fprintf(w, "    sample_ips: [%s]\n\n",
			joinStrings(limit(sortedStrings(ep.IPs), 10)))
	}

	// ---- Footer: global unique ports ----
	fmt.Fprintf(w, "\n# Observed destination ports (global)\n")
	for _, proto := range []string{"udp", "tcp"} {
		ports := sortedU16(globalPorts[proto])
		if len(ports) == 0 {
			continue
		}
		fmt.Fprintf(w, "- { proto: \"%s\", port: [%s] }\n",
			proto, joinU16(ports))
	}

	return nil
}

// ---------------- helpers ----------------

func dnsSuffix(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func sortedStrings(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func sortedKeysU16(m map[string]map[uint16]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedU16(m map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func joinStrings(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return "\"" + strings.Join(in, "\", \"") + "\""
}

func joinU16(in []uint16) string {
	if len(in) == 0 {
		return ""
	}
	sb := strings.Builder{}
	for i, p := range in {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf("%d", p))
	}
	return sb.String()
}
