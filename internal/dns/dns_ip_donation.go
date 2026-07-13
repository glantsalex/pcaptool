package dns

import (
	"net/netip"
	"sort"
	"strings"
)

type freshIPDNSDonorState struct {
	names          map[string]struct{}
	usedNormalized bool
}

// CompleteTopologyWithFreshIPDNSDonation upgrades weak public IPv4 topology
// rows from fresh same-run direct DNS evidence for the destination IP. Unlike
// exact endpoint donation, this intentionally crosses issuer, protocol, and
// port boundaries, so it only applies when the destination IP has exactly one
// effective direct DNS identity in the current run.
func CompleteTopologyWithFreshIPDNSDonation(entries []TopologyEntry) []TopologyEntry {
	if len(entries) == 0 {
		return entries
	}

	donors := make(map[string]*freshIPDNSDonorState, len(entries))
	for _, row := range entries {
		if !isFreshIPDNSDonor(row) {
			continue
		}
		ip, ok := publicIPv4TopologyDestination(row.DestinationIP)
		if !ok {
			continue
		}
		name := canonicalDNSName(row.DNSName)
		if !IsResolvableDNSName(name) {
			continue
		}
		state := donors[ip]
		if state == nil {
			state = &freshIPDNSDonorState{names: make(map[string]struct{}, 1)}
			donors[ip] = state
		}
		state.names[name] = struct{}{}
		if strings.EqualFold(strings.TrimSpace(row.DNSSource), "dns+synack+norm") {
			state.usedNormalized = true
		}
	}
	if len(donors) == 0 {
		return entries
	}

	out := append([]TopologyEntry(nil), entries...)
	for i := range out {
		row := &out[i]
		if !isFreshIPDNSRecipient(*row) {
			continue
		}
		ip, ok := publicIPv4TopologyDestination(row.DestinationIP)
		if !ok {
			continue
		}
		state := donors[ip]
		if state == nil {
			continue
		}
		name, ok := uniqueFreshIPDNSDonationName(state.names)
		if !ok {
			continue
		}
		row.DNSName = name
		if state.usedNormalized {
			row.DNSSource = "donated+ip+norm"
		} else {
			row.DNSSource = "donated+ip"
		}
	}
	return out
}

func isFreshIPDNSDonor(row TopologyEntry) bool {
	switch strings.ToLower(strings.TrimSpace(row.DNSSource)) {
	case "dns+synack", "dns+synack+norm":
		return strings.TrimSpace(row.DNSName) != ""
	default:
		return false
	}
}

func isFreshIPDNSRecipient(row TopologyEntry) bool {
	source := strings.ToLower(strings.TrimSpace(row.DNSSource))
	name := strings.TrimSpace(row.DNSName)
	if name == "" {
		return source == "" || source == "mid-session"
	}
	return source == "csv+mid" || source == "csv+conn"
}

func publicIPv4TopologyDestination(ip string) (string, bool) {
	canonical, ok := canonicalIPv4String(ip)
	if !ok {
		return "", false
	}
	addr, err := netip.ParseAddr(canonical)
	if err != nil || !isPublicIPv4(addr) {
		return "", false
	}
	return canonical, true
}

func uniqueFreshIPDNSDonationName(names map[string]struct{}) (string, bool) {
	if len(names) != 1 {
		return "", false
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	return ordered[0], true
}
