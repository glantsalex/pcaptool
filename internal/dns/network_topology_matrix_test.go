package dns

import (
	"net"
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

func TestBuildNetworkTopologyMatrixEntries_CSVConnSingleNameUsesFullFQDN(t *testing.T) {
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
	if row.DNSName != "europe-03.nominatim.openstreetmap.org" {
		t.Fatalf("expected full fqdn for csv+conn single-name IP, got %q", row.DNSName)
	}
	if row.DNSSource != "csv+conn" {
		t.Fatalf("expected source csv+conn, got %q", row.DNSSource)
	}
}

func TestCSVNameForIP_MultiNameIsRejectedAsAmbiguous(t *testing.T) {
	ipToDNS := map[string][]string{
		"203.0.113.10": {
			"api.store.ccv.eu",
			"mpush.store.ccv.eu",
		},
	}

	if gotConn, ok := csvNameForIP(ipToDNS, "203.0.113.10", false); ok || gotConn != "" {
		t.Fatalf("expected conn mode to reject ambiguous IP, got name=%q ok=%v", gotConn, ok)
	}

	if gotMid, ok := csvNameForIP(ipToDNS, "203.0.113.10", true); ok || gotMid != "" {
		t.Fatalf("expected mid mode to reject ambiguous IP, got name=%q ok=%v", gotMid, ok)
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

func TestBuildNetworkTopologyMatrixEntries_UnsortedKeepsIssuerFirstSeenOrder(t *testing.T) {
	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.0.0.9",
			DstIP:     "80.80.80.80",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC),
		},
		{
			IssuerIP:  "10.0.0.10",
			DstIP:     "90.90.90.90",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 1, 0, time.UTC),
		},
		{
			IssuerIP:  "10.0.0.9",
			DstIP:     "81.81.81.81",
			Protocol:  connectivity.ProtoTCP,
			Port:      8443,
			FirstSeen: time.Date(2026, 3, 1, 10, 0, 2, 0, time.UTC),
		},
	}

	opt := DefaultTopologyBuildOptions()
	opt.SortOutput = false

	out := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, nil, opt)
	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	if out[0].IssuerIP != "10.0.0.9" || out[1].IssuerIP != "10.0.0.9" || out[2].IssuerIP != "10.0.0.10" {
		t.Fatalf("expected issuer first-seen order with grouping preserved, got %#v", out)
	}
	if out[0].DestinationIP != "80.80.80.80" || out[1].DestinationIP != "81.81.81.81" {
		t.Fatalf("expected issuer-local discovery order preserved, got %#v", out)
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

func TestSquashNetworkTopologyShort_UnsortedKeepsIssuerFirstSeenOrder(t *testing.T) {
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
			IssuerIP:      "10.0.0.10",
			DestinationIP: "90.90.90.90",
			DNSName:       "three.example",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          443,
		},
		{
			IssuerIP:      "10.0.0.9",
			DestinationIP: "81.81.81.81",
			DNSName:       "two.example",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          8443,
		},
	}

	out := SquashNetworkTopologyShortWithOptions(in, false)
	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	if out[0].IssuerIP != "10.0.0.9" || out[1].IssuerIP != "10.0.0.9" || out[2].IssuerIP != "10.0.0.10" {
		t.Fatalf("expected issuer first-seen order with grouping preserved, got %#v", out)
	}
	if out[0].DestinationIP != "80.80.80.80" || out[1].DestinationIP != "81.81.81.81" {
		t.Fatalf("expected issuer-local discovery order preserved, got %#v", out)
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

func TestBuildNetworkTopologyMatrixEntries_StrongDNSSuppressesCSVConnSameTuple(t *testing.T) {
	p3000 := uint16(3000)
	txTime := time.Date(2026, 3, 3, 10, 0, 1, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("100.84.31.44"),
			DNSName:         "mpush3.whatspos.com",
			ResolvedIPs:     []net.IP{net.ParseIP("54.154.187.160")},
			DestinationPort: &p3000,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"54.154.187.160": EvDNSAnswer,
			},
		},
	}

	edges := []connectivity.Edge{
		// Earlier edge cannot match tx by time, so it would fall back to csv+conn.
		{
			IssuerIP:  "100.84.31.44",
			DstIP:     "54.154.187.160",
			Protocol:  connectivity.ProtoTCP,
			Port:      3000,
			FirstSeen: txTime.Add(-1 * time.Second),
		},
		// Later edge matches tx and produces strong dns+synack.
		{
			IssuerIP:  "100.84.31.44",
			DstIP:     "54.154.187.160",
			Protocol:  connectivity.ProtoTCP,
			Port:      3000,
			FirstSeen: txTime.Add(1 * time.Second),
		},
	}

	ipToDNS := map[string][]string{
		"54.154.187.160": {"mpush3.whatspos.com"},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 1 {
		t.Fatalf("expected 1 row after csv+conn suppression, got %d: %#v", len(out), out)
	}

	row := out[0]
	if row.DNSName != "mpush3.whatspos.com" {
		t.Fatalf("expected strong DNS name to win, got %q", row.DNSName)
	}
	if row.DNSSource != "dns+synack" {
		t.Fatalf("expected strong source dns+synack, got %q", row.DNSSource)
	}
}

func TestBuildNetworkTopologyMatrixEntries_StrongDNSSuppressesConflictingCSVCrossPort(t *testing.T) {
	p443 := uint16(443)
	txTime := time.Date(2026, 3, 4, 10, 0, 1, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.164.41.4"),
			DNSName:         "cpc.ocpp.amazon.eocharging.com",
			ResolvedIPs:     []net.IP{net.ParseIP("18.193.216.103")},
			DestinationPort: &p443,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"18.193.216.103": EvDNSAnswer,
			},
		},
	}

	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.164.41.4",
			DstIP:     "18.193.216.103",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: txTime.Add(1 * time.Second),
		},
		{
			IssuerIP:  "10.164.41.4",
			DstIP:     "18.193.216.103",
			Protocol:  connectivity.ProtoTCP,
			Port:      80,
			FirstSeen: txTime.Add(2 * time.Second),
		},
	}

	ipToDNS := map[string][]string{
		"18.193.216.103": {"google.com"},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 2 {
		t.Fatalf("expected exactly 2 rows (strong 443 + unresolved 80), got %d: %#v", len(out), out)
	}

	var (
		foundStrong443 bool
		foundMid80     bool
	)
	for _, row := range out {
		if row.DestinationIP != "18.193.216.103" || row.Protocol != "tcp" {
			continue
		}
		if row.Port == 443 && row.DNSName == "cpc.ocpp.amazon.eocharging.com" && row.DNSSource == "dns+synack" {
			foundStrong443 = true
		}
		if row.Port == 80 && row.DNSName == "" {
			foundMid80 = true
		}
	}

	if !foundStrong443 {
		t.Fatalf("expected strong dns+synack row on tcp/443")
	}
	if !foundMid80 {
		t.Fatalf("expected tcp/80 row to remain unresolved (conflicting csv suppressed)")
	}
}

func TestBuildNetworkTopologyMatrixEntries_PeerCompletionUsesUniqueDirectDonor(t *testing.T) {
	p8883 := uint16(8883)
	txTime := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.116.12.67"),
			DNSName:         "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c",
			ResolvedIPs:     []net.IP{net.ParseIP("13.55.209.128")},
			DestinationPort: &p8883,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"13.55.209.128": EvDNSAnswer,
			},
		},
	}

	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.116.12.67",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(1 * time.Second),
		},
		{
			IssuerIP:  "10.116.12.7",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(2 * time.Second),
		},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(out), out)
	}

	var foundPeer bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" {
				t.Fatalf("expected propagated DNS name, got %#v", row)
			}
			if row.DNSSource != "peer+ipport" {
				t.Fatalf("expected peer+ipport source, got %#v", row)
			}
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("expected unresolved peer row to be completed")
	}
}

func TestBuildNetworkTopologyMatrixEntries_PeerCompletionUsesUniqueInferredDonor(t *testing.T) {
	p8883 := uint16(8883)
	txTime := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.116.12.67"),
			DNSName:         "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c",
			ResolvedIPs:     []net.IP{net.ParseIP("13.55.209.128")},
			DestinationPort: &p8883,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"13.55.209.128": EvDNSAnswer | EvConnInferred,
			},
		},
	}

	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.116.12.67",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(1 * time.Second),
		},
		{
			IssuerIP:  "10.116.12.7",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(2 * time.Second),
		},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(out), out)
	}

	var foundPeer bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" {
				t.Fatalf("expected propagated DNS name, got %#v", row)
			}
			if row.DNSSource != "peer+ipport+conn" {
				t.Fatalf("expected peer+ipport+conn source, got %#v", row)
			}
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("expected unresolved peer row to be completed from inferred donor")
	}
}

func TestBuildNetworkTopologyMatrixEntries_PeerCompletionSkipsAmbiguousDonors(t *testing.T) {
	p8883 := uint16(8883)
	txTime := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.116.12.67"),
			DNSName:         "one.example",
			ResolvedIPs:     []net.IP{net.ParseIP("13.55.209.128")},
			DestinationPort: &p8883,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"13.55.209.128": EvDNSAnswer,
			},
		},
		{
			RequestTime:     txTime.Add(1 * time.Second),
			IssuerIP:        net.ParseIP("10.116.12.68"),
			DNSName:         "two.example",
			ResolvedIPs:     []net.IP{net.ParseIP("13.55.209.128")},
			DestinationPort: &p8883,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"13.55.209.128": EvDNSAnswer,
			},
		},
	}

	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.116.12.67",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(2 * time.Second),
		},
		{
			IssuerIP:  "10.116.12.68",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(3 * time.Second),
		},
		{
			IssuerIP:  "10.116.12.7",
			DstIP:     "13.55.209.128",
			Protocol:  connectivity.ProtoTCP,
			Port:      8883,
			FirstSeen: txTime.Add(4 * time.Second),
		},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	)

	var unresolvedFound bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "" {
				t.Fatalf("expected ambiguous donor tuple to remain unresolved, got %#v", row)
			}
			unresolvedFound = true
		}
	}
	if !unresolvedFound {
		t.Fatalf("expected unresolved row to remain present")
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
