// Package lsm builds public-destination logical service maps from finalized NTM rows.
package lsm

import "net/netip"

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, value := range values {
		out[i] = netip.MustParsePrefix(value)
	}
	return out
}

// Explicit special-use exclusions reproduce the artifact exercise's global
// unicast policy. IsGlobalUnicast alone admits RFC1918 and documentation ranges.
var nonPublic = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/3", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)
var publicExceptions = prefixes(
	"192.0.0.9/32", "192.0.0.10/32",
	"2001:1::1/128", "2001:1::2/128", "2001:3::/32",
	"2001:4:112::/48", "2001:20::/28", "2001:30::/28",
)
var ipv6Global = netip.MustParsePrefix("2000::/3")

// PublicDestination admits globally routable unicast destinations, including
// mapped IPv4 addresses under the equivalent IPv4 policy. Zone-scoped addresses
// and invalid addresses are never admitted.
func PublicDestination(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || (a.Is6() && !ipv6Global.Contains(a)) {
		return false
	}
	for _, p := range publicExceptions {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
