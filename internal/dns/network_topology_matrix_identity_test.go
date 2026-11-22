package dns

import (
	"net"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

func TestTopologyIdentityUsesSelectedObservationTime(t *testing.T) {
	hostnames := NewHostnames()

	const issuer = "10.180.1.10"
	const destination = "203.0.113.10"
	first := time.Date(2026, 11, 15, 2, 41, 0, 0, time.UTC)
	query := first.Add(2 * time.Minute)
	later := query.Add(500 * time.Millisecond)
	tx := &DNSTransaction{RequestTime: wireTime(query), wireEndpoints: makeEndpoints(net.ParseIP(issuer), nil), DNSNameID: hostnames.intern("device.example.test"), NameEvidence: EvDNSAnswer}
	tx.AddResolvedIP(net.ParseIP(destination), EvDNSAnswer)
	edges := []connectivity.Edge{{IssuerIP: issuer, DstIP: destination, Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: first, ObservedTimes: connectivity.NewObservationHistory(first, later)}}
	for _, tc := range []struct {
		name, early, late, want string
		withDNS                 bool
	}{
		{"mapping starts later", issuer, "123456789012345", "123456789012345", true},
		{"IP reassigned", "123456789012345", "223456789012345", "223456789012345", true},
		{"later mapping unknown", "123456789012345", issuer, issuer, true},
		{"fallback retains first observation", "123456789012345", "223456789012345", "123456789012345", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var times []time.Time
			label := func(ip string, at time.Time) string {
				if ip != issuer {
					t.Fatalf("unexpected IP %q", ip)
				}
				times = append(times, at)
				if at.Before(later) {
					return tc.early
				}
				return tc.late
			}
			var txs []*DNSTransaction
			expectedTime := first
			if tc.withDNS {
				txs = []*DNSTransaction{tx}
				expectedTime = later
			}
			got := BuildNetworkTopologyMatrixEntriesWithOptions(hostnames, txs, edges, label, nil, DefaultTopologyBuildOptions())
			if len(got) != 1 {
				t.Fatalf("rows=%+v", got)
			}
			row := got[0]
			if row.IssuerIP != tc.want || !row.ObservedAt.Equal(expectedTime) {
				t.Fatalf("row=%+v; want identity=%q at %s", row, tc.want, expectedTime)
			}
			if len(times) != 1 || !times[0].Equal(row.ObservedAt) {
				t.Fatalf("lookup times=%v row observation=%s", times, row.ObservedAt)
			}
			if tc.withDNS && (row.DNSName != "device.example.test" || row.DNSSource != "dns+synack") {
				t.Fatalf("DNS attribution changed: %+v", row)
			}
		})
	}
}
