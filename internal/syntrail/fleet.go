package syntrail

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// FleetSet identifies fleet hosts by canonical IPv4 addresses or device-pool prefixes.
type FleetSet struct {
	ips      map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

// LoadFleetIPv4File loads a fleet IPv4 address list from path.
func LoadFleetIPv4File(path string) (FleetSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return FleetSet{}, fmt.Errorf("open fleet IPv4 file %q: %w", path, err)
	}
	defer f.Close()

	fleet, err := ParseFleetIPv4List(f)
	if err != nil {
		return FleetSet{}, fmt.Errorf("parse fleet IPv4 file %q: %w", path, err)
	}
	return fleet, nil
}

// ParseFleetIPv4List parses a newline-delimited fleet IPv4 address list.
func ParseFleetIPv4List(r io.Reader) (FleetSet, error) {
	fleet := FleetSet{ips: make(map[netip.Addr]struct{})}

	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip, err := netip.ParseAddr(line)
		if err != nil {
			return FleetSet{}, fmt.Errorf("line %d: invalid IPv4 address %q: %w", lineNo, line, err)
		}
		if !ip.Is4() {
			return FleetSet{}, fmt.Errorf("line %d: expected IPv4 address, got %q", lineNo, line)
		}

		fleet.ips[ip] = struct{}{}
	}

	if err := sc.Err(); err != nil {
		return FleetSet{}, fmt.Errorf("line %d: scan fleet IPv4 list: %w", lineNo+1, err)
	}

	return fleet, nil
}

// Contains reports whether ip is in the fleet set.
func (f FleetSet) Contains(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if _, ok := f.ips[ip]; ok {
		return true
	}
	for _, prefix := range f.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseFleetSubnets parses an explicitly supplied, nonempty IPv4 device pool.
// Membership uses native prefixes; no individual addresses are enumerated.
func ParseFleetSubnets(values []string) (FleetSet, error) {
	if len(values) == 0 {
		return FleetSet{}, fmt.Errorf("fleet_subnets must not be empty")
	}
	fleet := FleetSet{}
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() {
			return FleetSet{}, fmt.Errorf("invalid IPv4 fleet subnet %q", value)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			fleet.prefixes = append(fleet.prefixes, prefix)
		}
	}
	return fleet, nil
}

func isLocalIPv4(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	octets := ip.As4()
	switch {
	case octets[0] == 10:
		return true
	case octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31:
		return true
	case octets[0] == 192 && octets[1] == 168:
		return true
	case octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127:
		return true
	default:
		return false
	}
}
