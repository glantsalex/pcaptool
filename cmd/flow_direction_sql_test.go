package cmd

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestFlowDirectionPrivateIPv4SQLUsesExactNetworkRanges(t *testing.T) {
	predicate := flowDirectionPrivateIPv4SQL("candidate_ip")
	wantPredicate := `COALESCE(
      (
        NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(candidate_ip), 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(candidate_ip), 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(candidate_ip), 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(candidate_ip), 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    )`
	if predicate != wantPredicate {
		t.Fatalf("private IPv4 predicate = %q, want %q", predicate, wantPredicate)
	}
	prefixes := flowDirectionPrivatePrefixesFromSQL(t, predicate, "candidate_ip")

	wantPrefixes := map[netip.Prefix]struct{}{
		netip.MustParsePrefix("10.0.0.0/8"):     {},
		netip.MustParsePrefix("172.16.0.0/12"):  {},
		netip.MustParsePrefix("192.168.0.0/16"): {},
		netip.MustParsePrefix("100.64.0.0/10"):  {},
	}
	if len(prefixes) != len(wantPrefixes) {
		t.Fatalf("private IPv4 prefix count = %d, want %d: %v", len(prefixes), len(wantPrefixes), prefixes)
	}
	for _, prefix := range prefixes {
		if _, ok := wantPrefixes[prefix]; !ok {
			t.Fatalf("unexpected private IPv4 prefix %s in generated SQL", prefix)
		}
		delete(wantPrefixes, prefix)
	}
	if len(wantPrefixes) != 0 {
		t.Fatalf("generated SQL missing private IPv4 prefixes: %v", wantPrefixes)
	}

	tests := []struct {
		address string
		want    bool
	}{
		{address: "10.0.0.0", want: true},
		{address: "10.0.0.1", want: true},
		{address: "10.1.2.3", want: true},
		{address: "10.255.255.255", want: true},
		{address: "172.16.0.0", want: true},
		{address: "172.16.0.1", want: true},
		{address: "172.31.255.254", want: true},
		{address: "172.31.255.255", want: true},
		{address: "192.168.0.0", want: true},
		{address: "192.168.1.1", want: true},
		{address: "192.168.255.255", want: true},
		{address: "100.64.0.0", want: true},
		{address: "100.64.0.1", want: true},
		{address: "100.65.1.1", want: true},
		{address: "100.104.1.1", want: true},
		{address: "100.127.255.254", want: true},
		{address: "100.127.255.255", want: true},
		{address: "172.15.255.254", want: false},
		{address: "172.15.255.255", want: false},
		{address: "172.32.0.0", want: false},
		{address: "172.32.0.1", want: false},
		{address: "100.63.255.254", want: false},
		{address: "100.63.255.255", want: false},
		{address: "100.128.0.0", want: false},
		{address: "100.128.0.1", want: false},
		{address: "8.8.8.8", want: false},
		{address: "not-an-ip", want: false},
		{address: "fd00::1", want: false},
		{address: "::ffff:10.0.0.1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := testAddressMatchesPrivatePrefixes(tt.address, prefixes); got != tt.want {
				t.Fatalf("generated private IPv4 predicate match for %q = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestFlowDirectionCorrectionSQLCGNATFleetLearnedServerDirection(t *testing.T) {
	tuple := syntrail.ServerTuple{
		DstIP:    netip.MustParseAddr("192.168.1.20"),
		DstPort:  80,
		Protocol: syntrail.ProtocolTCP,
	}
	sql := flowDirectionCorrectionSQL("net", []syntrail.ServerTuple{tuple})

	for _, want := range []string{
		flowDirectionPrivateIPv4SQL("src_ip") + " AS src_is_private",
		flowDirectionPrivateIPv4SQL("dst_ip") + " AS dst_is_private",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("flow direction SQL missing %q:\n%s", want, sql)
		}
	}
	genericClause := "WHEN (NOT src_is_private) AND dst_is_private\n" +
		"        THEN 'public_to_private_artifact'"
	learnedClause := "WHEN src_is_private\n" +
		"       AND dst_is_private\n" +
		"       AND protocol_lc = 'tcp'\n" +
		"       AND src_ip = '192.168.1.20'\n" +
		"       AND src_port = 80\n" +
		"        THEN 'private_server_192_168_1_20_80_tcp_seen_as_src_artifact'"
	genericIndex := strings.Index(sql, genericClause)
	if genericIndex == -1 {
		t.Fatalf("flow direction SQL missing generic direction clause:\n%s", sql)
	}
	learnedIndex := strings.Index(sql, learnedClause)
	if learnedIndex == -1 {
		t.Fatalf("flow direction SQL missing learned private-server clause:\n%s", sql)
	}
	if genericIndex >= learnedIndex {
		t.Fatalf("generic clause index %d, want before learned clause index %d", genericIndex, learnedIndex)
	}

	prefixes := flowDirectionPrivatePrefixesFromSQL(t, flowDirectionPrivateIPv4SQL("candidate_ip"), "candidate_ip")
	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		srcPort  uint16
		wantSwap string
	}{
		{
			name:    "correct fleet to server direction is retained",
			srcIP:   "100.65.1.1",
			dstIP:   "192.168.1.20",
			srcPort: 49152,
		},
		{
			name:     "reversed server to fleet direction uses learned server tuple",
			srcIP:    "192.168.1.20",
			dstIP:    "100.65.1.1",
			srcPort:  80,
			wantSwap: "private_server_192_168_1_20_80_tcp_seen_as_src_artifact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := testFlowDirectionSwapReason(tt.srcIP, tt.dstIP, tt.srcPort, "tcp", prefixes, []syntrail.ServerTuple{tuple})
			if got != tt.wantSwap {
				t.Fatalf("swap reason = %q, want %q", got, tt.wantSwap)
			}
		})
	}
}

func flowDirectionPrivatePrefixesFromSQL(t *testing.T, predicate, column string) []netip.Prefix {
	t.Helper()
	pattern := regexp.MustCompile(
		`NET\.IP_TRUNC\(NET\.SAFE_IP_FROM_STRING\(` + regexp.QuoteMeta(column) + `\), ([0-9]+)\) = NET\.IP_FROM_STRING\('([^']+)'\)`,
	)
	matches := pattern.FindAllStringSubmatch(predicate, -1)
	if len(matches) == 0 {
		t.Fatalf("no private IPv4 network terms found in generated SQL predicate %q", predicate)
	}

	prefixes := make([]netip.Prefix, 0, len(matches))
	for _, match := range matches {
		bits, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatalf("parse prefix length %q: %v", match[1], err)
		}
		prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", match[2], bits))
		if err != nil {
			t.Fatalf("parse generated private IPv4 prefix %q/%d: %v", match[2], bits, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func testAddressMatchesPrivatePrefixes(address string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() || addr.Is4In6() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func testFlowDirectionSwapReason(
	srcIP string,
	dstIP string,
	srcPort uint16,
	protocol string,
	prefixes []netip.Prefix,
	tuples []syntrail.ServerTuple,
) string {
	srcPrivate := testAddressMatchesPrivatePrefixes(srcIP, prefixes)
	dstPrivate := testAddressMatchesPrivatePrefixes(dstIP, prefixes)
	if !srcPrivate && dstPrivate {
		return "public_to_private_artifact"
	}
	for _, tuple := range tuples {
		if srcPrivate && dstPrivate &&
			strings.EqualFold(protocol, string(tuple.Protocol)) &&
			srcIP == tuple.DstIP.String() &&
			srcPort == tuple.DstPort {
			return privateServerSwapReason(tuple)
		}
	}
	return ""
}
