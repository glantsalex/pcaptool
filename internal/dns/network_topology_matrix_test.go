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

func TestBuildNetworkTopologyMatrixEntries_EVSECSVMidForMappedIPs(t *testing.T) {
	edges := []connectivity.Edge{
		{IssuerIP: "10.93.3.28", DstIP: "63.183.18.177", Protocol: connectivity.ProtoTCP, Port: 443},
		{IssuerIP: "10.93.3.28", DstIP: "63.184.210.25", Protocol: connectivity.ProtoTCP, Port: 443},
	}
	ipToDNS := map[string][]string{
		"63.183.18.177": {"evse.total-ev-charge.com"},
		"63.184.210.25": {"evse.total-ev-charge.com"},
	}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, ipToDNS, DefaultTopologyBuildOptions())
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %#v", len(got), got)
	}
	for _, row := range got {
		if row.DNSName != "evse.total-ev-charge.com" || row.DNSSource != "csv+mid" {
			t.Fatalf("mapped EVSE row lost CSV attribution: %#v", row)
		}
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

func TestCSVNameForIP_EVSEMappedIPsReturnExactCanonicalName(t *testing.T) {
	ipToDNS := map[string][]string{
		"63.183.18.177": {"EVSE.Total-EV-Charge.COM."},
		"63.184.210.25": {"evse.total-ev-charge.com"},
	}

	for _, ip := range []string{"63.183.18.177", "63.184.210.25"} {
		got, ok := csvNameForIP(ipToDNS, ip, true)
		if !ok || got != "evse.total-ev-charge.com" {
			t.Fatalf("csvNameForIP(%q)=(%q,%v), want canonical EVSE name", ip, got, ok)
		}
	}
}

func TestBuildNetworkTopologyMatrixEntries_AmbiguousCSVRemainsUnresolved(t *testing.T) {
	edges := []connectivity.Edge{{
		IssuerIP: "10.93.3.28",
		DstIP:    "63.184.210.25",
		Protocol: connectivity.ProtoTCP,
		Port:     443,
	}}
	ipToDNS := map[string][]string{
		"63.184.210.25": {"evse.total-ev-charge.com", "other.example.com"},
	}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, ipToDNS, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	if got[0].DNSName != "" || got[0].DNSSource != "mid-session" {
		t.Fatalf("ambiguous CSV unexpectedly attributed row: %#v", got[0])
	}
}

func TestCompleteTopologyWithActiveDNSConservativeCompletion(t *testing.T) {
	in := []TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.2", DestinationIP: "8.8.4.4", DNSName: "already.example", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.3", DestinationIP: "9.9.9.9", DNSName: " ", DNSSource: "mid-session", Protocol: "udp", Port: 1234},
		{IssuerIP: "10.0.0.4", DestinationIP: "1.1.1.1", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.5", DestinationIP: "10.1.2.3", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.6", DestinationIP: "2001:4860:4860::8888", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.7", DestinationIP: "4.4.4.4", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 443},
	}
	resolutions := []DNSNameIPv4Resolution{
		{DNSName: " API.EXAMPLE.COM. ", IPv4s: []string{"8.8.8.8", "8.8.4.4", "10.1.2.3", "2001:4860:4860::8888"}},
		{DNSName: "one.example.com", IPv4s: []string{"9.9.9.9"}},
		{DNSName: "two.example.com", IPv4s: []string{"9.9.9.9"}},
		{DNSName: "cloud.example.com", IPv4s: []string{"1.1.1.1"}},
	}

	got := CompleteTopologyWithActiveDNS(in, resolutions)
	if got[0].DNSName != "api.example.com" || got[0].DNSSource != "active+matrix" {
		t.Fatalf("unique public match not completed: %#v", got[0])
	}
	if got[1].DNSName != "already.example" || got[1].DNSSource != "dns+synack" {
		t.Fatalf("existing attribution was overwritten: %#v", got[1])
	}
	for _, idx := range []int{2, 4, 5, 6} {
		if got[idx].DNSName != in[idx].DNSName || got[idx].DNSSource != in[idx].DNSSource {
			t.Fatalf("row %d unexpectedly completed: got=%#v input=%#v", idx, got[idx], in[idx])
		}
	}
	if got[3].DNSName != "cloud.example.com" || got[3].DNSSource != "active+matrix" {
		t.Fatalf("second unique public match not completed: %#v", got[3])
	}
	if in[0].DNSName != "" || in[0].DNSSource != "mid-session" {
		t.Fatalf("input topology mutated: %#v", in[0])
	}
}

func TestCompleteTopologyWithActiveDNSDoesNotMutateTransactionsOrCSVLearning(t *testing.T) {
	tx := &DNSTransaction{DNSName: "api.example.com", IssuerIP: net.ParseIP("10.0.0.1")}
	got := CompleteTopologyWithActiveDNS(
		[]TopologyEntry{{
			IssuerIP:      "10.0.0.1",
			DestinationIP: "8.8.8.8",
			Protocol:      "tcp",
			Port:          443,
		}},
		[]DNSNameIPv4Resolution{{DNSName: "api.example.com", IPv4s: []string{"8.8.8.8"}}},
	)
	if got[0].DNSName != "api.example.com" || got[0].DNSSource != "active+matrix" {
		t.Fatalf("topology was not completed: %#v", got)
	}
	if len(tx.ResolvedIPs) != 0 || tx.NameEvidence != EvNone {
		t.Fatalf("active matrix completion mutated transaction: %#v", tx)
	}
	if learned := StrongObservedIPDNSPairsFromTransactions([]*DNSTransaction{tx}); len(learned) != 0 {
		t.Fatalf("active matrix completion produced CSV learning candidates: %#v", learned)
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

func TestBuildNetworkTopologyMatrixEntries_UniqueCSVMidSurvivesConflictingStrongDNSCrossPort(t *testing.T) {
	p9999 := uint16(9999)
	txTime := time.Date(2026, 3, 4, 10, 0, 1, 0, time.UTC)

	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.93.3.28"),
			DNSName:         "different.example.com",
			ResolvedIPs:     []net.IP{net.ParseIP("63.184.210.25")},
			DestinationPort: &p9999,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"63.184.210.25": EvDNSAnswer,
			},
		},
	}

	edges := []connectivity.Edge{
		{
			IssuerIP:  "10.93.3.28",
			DstIP:     "63.184.210.25",
			Protocol:  connectivity.ProtoTCP,
			Port:      9999,
			FirstSeen: txTime.Add(1 * time.Second),
		},
		{
			IssuerIP:  "10.93.3.28",
			DstIP:     "63.184.210.25",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: txTime.Add(2 * time.Second),
		},
	}

	ipToDNS := map[string][]string{
		"63.184.210.25": {"EVSE.Total-EV-Charge.COM."},
	}

	out := BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)

	if len(out) != 2 {
		t.Fatalf("expected strong 9999 and csv+mid 443 rows, got %d: %#v", len(out), out)
	}

	var (
		foundStrong9999 bool
		foundCSV443     bool
	)
	for _, row := range out {
		if row.DestinationIP != "63.184.210.25" || row.Protocol != "tcp" {
			continue
		}
		if row.Port == 9999 && row.DNSName == "different.example.com" && row.DNSSource == "dns+synack" {
			foundStrong9999 = true
		}
		if row.Port == 443 && row.DNSName == "evse.total-ev-charge.com" && row.DNSSource == "csv+mid" {
			foundCSV443 = true
		}
	}

	if !foundStrong9999 {
		t.Fatalf("expected conflicting strong dns+synack row on tcp/9999")
	}
	if !foundCSV443 {
		t.Fatalf("expected authoritative csv+mid row on tcp/443 to survive cross-port cleanup")
	}
}

func TestClassifyDNSDonationDonor(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   dnsDonationDonorTier
	}{
		{name: "direct DNS", source: "dns+synack", want: dnsDonationDonorDirect},
		{name: "direct SNI normalized", source: " SNI+SYNACK ", want: dnsDonationDonorDirect},
		{name: "DNS connection inferred normalized", source: " DNS+CONN+SYNACK ", want: dnsDonationDonorInferred},
		{name: "SNI connection inferred", source: "sni+conn+synack", want: dnsDonationDonorNone},
		{name: "DNS connection only", source: "dns+conn", want: dnsDonationDonorNone},
		{name: "SNI connection only", source: "sni+conn", want: dnsDonationDonorNone},
		{name: "CSV connection", source: "csv+conn", want: dnsDonationDonorNone},
		{name: "CSV mid-session", source: "csv+mid", want: dnsDonationDonorNone},
		{name: "mid-session", source: "mid-session", want: dnsDonationDonorNone},
		{name: "legacy peer", source: "peer+ipport", want: dnsDonationDonorNone},
		{name: "previous donation", source: "donated+ipport", want: dnsDonationDonorNone},
		{name: "active completion", source: "active+matrix", want: dnsDonationDonorNone},
		{name: "placeholder", source: "placeholder", want: dnsDonationDonorNone},
		{name: "arbitrary future connection", source: "future+conn", want: dnsDonationDonorNone},
		{name: "empty", source: "", want: dnsDonationDonorNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDNSDonationDonor(tt.source); got != tt.want {
				t.Fatalf("classifyDNSDonationDonor(%q)=%v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func TestDNSDonationName(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{name: "none", want: ""},
		{name: "one name stays full", names: []string{"api.eu.example.com"}, want: "api.eu.example.com"},
		{name: "common suffix", names: []string{"web.us.example.com", "api.eu.example.com"}, want: "example.com"},
		{name: "longer common suffix", names: []string{"b.service.example.com", "a.service.example.com"}, want: "service.example.com"},
		{name: "total ev charge suffix", names: []string{"evse.total-ev-charge.com", "api.total-ev-charge.com"}, want: "total-ev-charge.com"},
		{name: "amazonaws suffix", names: []string{"broker.iot.ap-southeast-2.amazonaws.com", "bucket.s3.amazonaws.com"}, want: "amazonaws.com"},
		{name: "two-label co uk suffix", names: []string{"api.example.co.uk", "web.other.co.uk"}, want: "co.uk"},
		{name: "one label is insufficient", names: []string{"one.example", "two.example"}, want: ""},
		{name: "no suffix", names: []string{"api.example.com", "api.example.net"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := make(map[string]struct{}, len(tt.names))
			for _, name := range tt.names {
				names[name] = struct{}{}
			}
			if got := dnsDonationName(names); got != tt.want {
				t.Fatalf("dnsDonationName(%v)=%q, want %q", tt.names, got, tt.want)
			}
		})
	}
}

func TestCompleteTopologyWithDNSDonationTierSuffixAndRecipientRules(t *testing.T) {
	const (
		ip    = "8.8.8.8"
		proto = "tcp"
		port  = uint16(443)
	)

	tests := []struct {
		name       string
		donors     []TopologyEntry
		recipient  TopologyEntry
		wantName   string
		wantSource string
	}{
		{
			name:       "A single direct name donates full",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: " API.EXAMPLE.COM. ", DNSSource: "dns+synack", Protocol: proto, Port: port}},
			recipient:  TopologyEntry{DNSSource: " Mid-Session "},
			wantName:   "api.example.com",
			wantSource: "donated+ipport",
		},
		{
			name: "B multiple direct names donate common suffix",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "api.eu.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "web.us.example.com", DNSSource: "sni+synack", Protocol: proto, Port: port},
			},
			wantName:   "example.com",
			wantSource: "donated+ipport",
		},
		{
			name: "C no two-label direct suffix does not donate",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "one.example", DNSSource: "dns+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "two.example", DNSSource: "dns+synack", Protocol: proto, Port: port},
			},
			wantSource: "mid-session",
		},
		{
			name: "D direct tier wins over inferred",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "inferred.other.net", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
			},
			wantName:   "direct.example.com",
			wantSource: "donated+ipport",
		},
		{
			name: "D direct tier prevents inferred fallback",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "one.example", DNSSource: "dns+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "two.example", DNSSource: "sni+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "usable.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
			},
			wantSource: "mid-session",
		},
		{
			name:       "E single inferred name donates full",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "inferred.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port}},
			wantName:   "inferred.example.com",
			wantSource: "donated+ipport+conn",
		},
		{
			name: "F multiple inferred names donate common suffix",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "one.service.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "two.service.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
			},
			wantName:   "service.example.com",
			wantSource: "donated+ipport+conn",
		},
		{
			name:       "G SNI inferred cannot donate",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "unsafe.example.com", DNSSource: "sni+conn+synack", Protocol: proto, Port: port}},
			wantSource: "mid-session",
		},
		{
			name:       "H exact tuple only",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port + 1}},
			wantSource: "mid-session",
		},
		{
			name:       "I attributed source cannot receive",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port}},
			recipient:  TopologyEntry{DNSSource: "csv+mid"},
			wantSource: "csv+mid",
		},
		{
			name:       "I named PTR recipient remains unchanged",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port}},
			recipient:  TopologyEntry{DNSName: "ptr.example.net", DNSSource: "ptr+matrix"},
			wantName:   "ptr.example.net",
			wantSource: "ptr+matrix",
		},
		{
			name:       "I named CSV recipient remains unchanged",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port}},
			recipient:  TopologyEntry{DNSName: "csv.example.net", DNSSource: "csv+mid"},
			wantName:   "csv.example.net",
			wantSource: "csv+mid",
		},
		{
			name:       "J donated source cannot recursively receive",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "donated+ipport", Protocol: proto, Port: port}},
			wantSource: "mid-session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recipient := tt.recipient
			recipient.DestinationIP = ip
			recipient.Protocol = " TCP "
			recipient.Port = port
			if recipient.DNSSource == "" {
				recipient.DNSSource = "mid-session"
			}
			entries := append(append([]TopologyEntry(nil), tt.donors...), recipient)
			got := CompleteTopologyWithDNSDonation(entries)[len(entries)-1]
			if got.DNSName != tt.wantName || got.DNSSource != tt.wantSource {
				t.Fatalf("recipient=(name %q, source %q), want (%q, %q)", got.DNSName, got.DNSSource, tt.wantName, tt.wantSource)
			}
		})
	}
}

func TestCompleteTopologyWithDNSDonationAcceptsDirectDNSAndSNI(t *testing.T) {
	in := []TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: " 8.8.8.8 ", DNSName: "API.EXAMPLE.COM.", DNSSource: "dns+synack", Protocol: " TCP ", Port: 443},
		{IssuerIP: "10.0.0.2", DestinationIP: "8.8.8.8", DNSName: "api.example.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.3", DestinationIP: "8.8.8.8", DNSName: " \t", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.4", DestinationIP: "1.1.1.1", DNSName: "SNI.EXAMPLE.COM.", DNSSource: "sni+synack", Protocol: "tcp", Port: 8443},
		{IssuerIP: "10.0.0.5", DestinationIP: "1.1.1.1", DNSName: "", DNSSource: "mid-session", Protocol: " TCP", Port: 8443},
		{IssuerIP: "10.0.0.6", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 443},
	}

	got := CompleteTopologyWithDNSDonation(in)
	for _, idx := range []int{2, 4, 5} {
		if got[idx].DNSSource != "donated+ipport" {
			t.Fatalf("row %d source=%q, want donated+ipport: %#v", idx, got[idx].DNSSource, got[idx])
		}
	}
	if got[2].DNSName != "api.example.com" {
		t.Fatalf("canonical DNS donation=%q, want api.example.com", got[2].DNSName)
	}
	if got[4].DNSName != "sni.example.com" {
		t.Fatalf("canonical SNI donation=%q, want sni.example.com", got[4].DNSName)
	}
	if got[5].DNSName != "api.example.com" {
		t.Fatalf("empty-source recipient donation=%q, want api.example.com", got[5].DNSName)
	}
	if in[2].DNSName != " \t" || in[4].DNSName != "" {
		t.Fatalf("input entries were mutated: %#v", in)
	}
}

func TestCompleteTopologyWithDNSDonationIsolatesKeyAndPreservesAttribution(t *testing.T) {
	in := []TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.2", DestinationIP: "8.8.4.4", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.3", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session", Protocol: "udp", Port: 443},
		{IssuerIP: "10.0.0.4", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 8443},
		{IssuerIP: "10.0.0.5", DestinationIP: "8.8.8.8", DNSName: "keep.example.com", DNSSource: "csv+conn", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.6", DestinationIP: "10.1.2.3", DNSName: "private.example.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.7", DestinationIP: "10.1.2.3", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.8", DestinationIP: "9.9.9.9", DNSName: "zero-port.example.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 0},
		{IssuerIP: "10.0.0.9", DestinationIP: "9.9.9.9", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 0},
	}

	got := CompleteTopologyWithDNSDonation(in)
	for _, idx := range []int{1, 2, 3, 6, 8} {
		if got[idx].DNSName != "" || got[idx].DNSSource != in[idx].DNSSource {
			t.Fatalf("isolated/private row %d was completed: %#v", idx, got[idx])
		}
	}
	if got[4].DNSName != "keep.example.com" || got[4].DNSSource != "csv+conn" {
		t.Fatalf("existing attribution was overwritten: %#v", got[4])
	}
}

func TestCompleteTopologyWithDNSDonationRejectsUnsafeSources(t *testing.T) {
	unsafeSources := []string{
		"sni+conn+synack",
		"dns+conn",
		"sni+conn",
		"csv+conn",
		"csv+mid",
		"csv+synack",
		"mid-session",
		"ptr+matrix",
		"ptr-normalized+matrix",
		"ptr+fcrdns+matrix",
		"tls-cert-san+matrix",
		"active",
		"active+synack",
		"active+matrix",
		"peer+ipport",
		"peer+ipport+conn",
		"donated+ipport",
		"donated+ipport+conn",
		"placeholder",
		"future+conn",
		"unknown",
		"",
	}

	for _, source := range unsafeSources {
		t.Run(source, func(t *testing.T) {
			got := CompleteTopologyWithDNSDonation([]TopologyEntry{
				{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "unsafe.example.com", DNSSource: source, Protocol: "tcp", Port: 443},
				{IssuerIP: "10.0.0.2", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
			})
			if got[1].DNSName != "" || got[1].DNSSource != "mid-session" {
				t.Fatalf("source %q donated unexpectedly: %#v", source, got[1])
			}
		})
	}
}

func TestCompleteTopologyWithDNSDonationUsesUniqueDirectDonor(t *testing.T) {
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

	out := CompleteTopologyWithDNSDonation(BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	))

	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(out), out)
	}

	var foundPeer bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" {
				t.Fatalf("expected propagated DNS name, got %#v", row)
			}
			if row.DNSSource != "donated+ipport" {
				t.Fatalf("expected donated+ipport source, got %#v", row)
			}
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("expected unresolved peer row to be completed")
	}
}

func TestCompleteTopologyWithDNSDonationDoesNotCrossDestinationIP(t *testing.T) {
	p443 := uint16(443)
	txTime := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.116.12.67"),
			DNSName:         "direct.example.com",
			ResolvedIPs:     []net.IP{net.ParseIP("13.55.209.128")},
			DestinationPort: &p443,
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
			Port:      443,
			FirstSeen: txTime.Add(time.Second),
		},
		{
			IssuerIP:  "10.116.12.67",
			DstIP:     "13.55.209.129",
			Protocol:  connectivity.ProtoTCP,
			Port:      443,
			FirstSeen: txTime.Add(2 * time.Second),
		},
	}

	out := CompleteTopologyWithDNSDonation(BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, DefaultTopologyBuildOptions()))
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(out), out)
	}
	for _, row := range out {
		switch row.DestinationIP {
		case "13.55.209.128":
			if row.DNSName != "direct.example.com" || row.DNSSource != "dns+synack" {
				t.Fatalf("direct donor row changed: %#v", row)
			}
		case "13.55.209.129":
			if row.DNSName != "" || row.DNSSource != "mid-session" {
				t.Fatalf("direct donor crossed destination IP: %#v", row)
			}
		default:
			t.Fatalf("unexpected destination row: %#v", row)
		}
	}
}

func TestCompleteTopologyWithDNSDonationUsesUniqueInferredDonor(t *testing.T) {
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

	out := CompleteTopologyWithDNSDonation(BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	))

	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(out), out)
	}

	var foundDonor, foundCompletedPeer bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.67" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" || row.DNSSource != "dns+conn+synack" {
				t.Fatalf("inferred donor row changed unexpectedly: %#v", row)
			}
			foundDonor = true
		}
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" || row.DNSSource != "donated+ipport+conn" {
				t.Fatalf("inferred donor did not complete peer row: %#v", row)
			}
			foundCompletedPeer = true
		}
	}
	if !foundDonor || !foundCompletedPeer {
		t.Fatalf("expected unchanged donor and completed peer; got %#v", out)
	}
}

func TestCompleteTopologyWithDNSDonationKeepsInferredDonationOnExactDestination(t *testing.T) {
	p443 := uint16(443)
	txTime := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	txs := []*DNSTransaction{
		{
			RequestTime:     txTime,
			IssuerIP:        net.ParseIP("10.245.200.86"),
			DNSName:         "www.cisco.com",
			ResolvedIPs:     []net.IP{net.ParseIP("3.5.120.27")},
			DestinationPort: &p443,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"3.5.120.27": EvDNSAnswer | EvConnInferred,
			},
		},
		{
			RequestTime:     txTime.Add(time.Second),
			IssuerIP:        net.ParseIP("10.118.217.9"),
			DNSName:         "www.cisco.com",
			ResolvedIPs:     []net.IP{net.ParseIP("52.219.170.186")},
			DestinationPort: &p443,
			ProtocolL4:      L4ProtoTCP,
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"52.219.170.186": EvDNSAnswer | EvConnInferred,
			},
		},
	}
	edges := []connectivity.Edge{
		{IssuerIP: "10.245.200.86", DstIP: "3.5.120.27", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: txTime.Add(2 * time.Second)},
		{IssuerIP: "10.245.214.82", DstIP: "3.5.120.27", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: txTime.Add(3 * time.Second)},
		{IssuerIP: "10.118.217.9", DstIP: "52.219.170.186", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: txTime.Add(4 * time.Second)},
		{IssuerIP: "10.118.216.36", DstIP: "52.219.170.186", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: txTime.Add(5 * time.Second)},
	}

	out := CompleteTopologyWithDNSDonation(BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, DefaultTopologyBuildOptions()))
	if len(out) != 4 {
		t.Fatalf("expected 4 rows, got %d: %#v", len(out), out)
	}

	donors, completedPeers := 0, 0
	for _, row := range out {
		switch row.DNSSource {
		case "dns+conn+synack":
			if row.DNSName != "www.cisco.com" {
				t.Fatalf("unexpected inferred donor name: %#v", row)
			}
			donors++
		case "donated+ipport+conn":
			if row.DNSName != "www.cisco.com" {
				t.Fatalf("unexpected inferred donation: %#v", row)
			}
			completedPeers++
		default:
			t.Fatalf("unexpected row source: %#v", row)
		}
	}
	if donors != 2 || completedPeers != 2 {
		t.Fatalf("donors=%d completed_peers=%d, want 2 each; out=%#v", donors, completedPeers, out)
	}
}

func TestCompleteTopologyWithDNSDonationSkipsAmbiguousDonors(t *testing.T) {
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

	out := CompleteTopologyWithDNSDonation(BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	))

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
