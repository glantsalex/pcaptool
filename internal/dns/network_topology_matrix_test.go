package dns

import (
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

func TestBuildNetworkTopologyMatrixEntries_CSVMidSingleNameUsesFullFQDNAndDedups(t *testing.T) {
	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.10.10.10",
			DstIP:     "153.46.253.156",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 2, 9, 7, 10, 39, 0, time.UTC),
		},
		{
			IssuerIP:  "10.10.10.10",
			DstIP:     "153.46.253.156",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 2, 9, 7, 10, 40, 0, time.UTC),
		},
	}

	ipToDNS := map[string][]string{
		"153.46.253.156": {"europe-03.nominatim.openstreetmap.org"},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		nil,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 1 {
		t.Fatalf("expected 1 deduped row, got %d", len(out))
	}

	row := out[0]
	if row.DNSName != "europe-03.nominatim.openstreetmap.org" {
		t.Fatalf("expected full fqdn for csv+mid, got %q", row.DNSName)
	}
	if row.DNSSource != "csv+mid" {
		t.Fatalf("expected source csv+mid, got %q", row.DNSSource)
	}
}

func TestBuildNetworkTopologyMatrixEntries_CSVConnSingleNameKeepsTLD1(t *testing.T) {
	edges := []connectivity.Edge{
		{
			IssuerIP:  "44.44.44.44",
			DstIP:     "153.46.253.156",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 2, 9, 7, 10, 39, 0, time.UTC),
		},
	}

	ipToDNS := map[string][]string{
		"153.46.253.156": {"europe-03.nominatim.openstreetmap.org"},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		nil,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}

	row := out[0]
	if row.DNSName != "openstreetmap.org" {
		t.Fatalf("expected tld+1 for csv+conn, got %q", row.DNSName)
	}
	if row.DNSSource != "csv+conn" {
		t.Fatalf("expected source csv+conn, got %q", row.DNSSource)
	}
}

func TestBuildNetworkTopologyMatrixEntries_SortsIssuersByEndpointCountDesc(t *testing.T) {
	// 10.0.0.9 has two unique endpoints (same dst, different ports).
	// 10.0.0.10 has one endpoint.
	// Order must be by endpoint count desc, not issuer lexical order.
	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.0.0.9",
			DstIP:     "80.80.80.80",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC),
		},
		{
			IssuerIP:  "10.0.0.9",
			DstIP:     "80.80.80.80",
			Protocol:  connectivity.ProtoTCP,
			Port:      8443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 1, 0, time.UTC),
		},
		{
			IssuerIP:  "10.0.0.10",
			DstIP:     "90.90.90.90",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 2, 0, time.UTC),
		},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		nil,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	if out[0].IssuerIP != "10.0.0.9" {
		t.Fatalf("expected issuer with most endpoints first, got %q", out[0].IssuerIP)
	}
}

func TestSquashNetworkTopologyShort_SortsIssuersByEndpointCountDesc(t *testing.T) {
	in := []TopologyEntry{
		{
			IssuerIP:      "10.0.0.9",
			DestinationIP: "80.80.80.80",
			DNSName:       "one.example",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          443,
		},
		{
			IssuerIP:      "10.0.0.9",
			DestinationIP: "80.80.80.80",
			DNSName:       "two.example",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          8443,
		},
		{
			IssuerIP:      "10.0.0.10",
			DestinationIP: "90.90.90.90",
			DNSName:       "three.example",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          443,
		},
	}

	out := SquashNetworkTopologyShort(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	if out[0].IssuerIP != "10.0.0.9" {
		t.Fatalf("expected issuer with most endpoints first, got %q", out[0].IssuerIP)
	}
}

func TestBuildNetworkTopologyMatrixEntries_PrivateDestinationIsLastWithinIssuer(t *testing.T) {
	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.244.34.239",
			DstIP:     "1.1.1.1",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		},
		{
			IssuerIP:  "10.244.34.239",
			DstIP:     "34.253.43.136",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 2, 10, 0, 1, 0, time.UTC),
		},
		{
			IssuerIP:  "10.244.34.239",
			DstIP:     "10.4.17.52",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: time.Date(2026, 3, 2, 10, 0, 2, 0, time.UTC),
		},
	}

	ipToDNS := map[string][]string{
		"1.1.1.1": {"one.one.one.one"},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		nil,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	if out[2].DestinationIP != "10.4.17.52" {
		t.Fatalf("expected private destination last, got last=%q", out[2].DestinationIP)
	}
}

func TestSquashNetworkTopologyShort_PrivateDestinationIsLastWithinIssuer(t *testing.T) {
	in := []TopologyEntry{
		{
			IssuerIP:      "10.244.34.239",
			DestinationIP: "10.4.100.58",
			DNSName:       "",
			DNSSource:     "",
			Protocol:      "tcp",
			Port:          1883,
		},
		{
			IssuerIP:      "10.244.34.239",
			DestinationIP: "34.253.43.136",
			DNSName:       "",
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          443,
		},
	}

	out := SquashNetworkTopologyShort(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[1].DestinationIP != "10.4.100.58" {
		t.Fatalf("expected private destination last, got last=%q", out[1].DestinationIP)
	}
}
