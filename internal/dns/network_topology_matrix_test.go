package dns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

func assertNoTopologyRowsWithDNSNameAndEmptySource(t *testing.T, entries []TopologyEntry) {
	t.Helper()
	for _, row := range entries {
		if strings.TrimSpace(row.DNSName) != "" && strings.TrimSpace(row.DNSSource) == "" {
			t.Fatalf("topology row has DNSName without DNSSource: %#v", row)
		}
	}
}

func findTopologyRow(entries []TopologyEntry, issuer, dst, proto string, port uint16) (TopologyEntry, bool) {
	for _, row := range entries {
		if row.IssuerIP == issuer &&
			row.DestinationIP == dst &&
			row.Protocol == proto &&
			row.Port == port {
			return row, true
		}
	}
	return TopologyEntry{}, false
}

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
	assertNoTopologyRowsWithDNSNameAndEmptySource(t, got)
}

func TestNetworkTopologyMatrixDoesNotEmitDNSNameWithoutSource(t *testing.T) {
	const (
		issuer = "10.118.229.71"
		dst    = "48.209.138.168"
		name   = "settings-win.data.microsoft.com"
	)
	txTime := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	txs := []*DNSTransaction{{
		RequestTime: txTime,
		IssuerIP:    net.ParseIP(issuer),
		DNSName:     name,
		ResolvedIPs: []net.IP{net.ParseIP(dst)},
	}}
	edges := []connectivity.Edge{{
		IssuerIP:  issuer,
		DstIP:     dst,
		Protocol:  connectivity.ProtoTCP,
		Port:      443,
		FirstSeen: txTime.Add(100 * time.Millisecond),
	}}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	assertNoTopologyRowsWithDNSNameAndEmptySource(t, got)
	if got[0].DNSName == name {
		t.Fatalf("evidence-less transaction DNS name was emitted: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixStillEmitsDNSSynackForEvidenceBackedTransaction(t *testing.T) {
	const (
		issuer = "10.118.229.71"
		dst    = "48.209.138.168"
		name   = "settings-win.data.microsoft.com"
	)
	txTime := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	tx := &DNSTransaction{
		RequestTime:  txTime,
		IssuerIP:     net.ParseIP(issuer),
		DNSName:      name,
		NameEvidence: EvDNSAnswer,
	}
	tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer)
	edges := []connectivity.Edge{{
		IssuerIP:  issuer,
		DstIP:     dst,
		Protocol:  connectivity.ProtoTCP,
		Port:      443,
		FirstSeen: txTime.Add(100 * time.Millisecond),
	}}

	got := BuildNetworkTopologyMatrixEntriesWithOptions([]*DNSTransaction{tx}, edges, nil, nil, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	assertNoTopologyRowsWithDNSNameAndEmptySource(t, got)
	if got[0].DNSName != name || got[0].DNSSource != "dns+synack" {
		t.Fatalf("evidence-backed transaction was not emitted as dns+synack: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixCSVFallbackStillHasSource(t *testing.T) {
	const (
		issuer = "10.93.3.28"
		dst    = "48.209.138.168"
		name   = "settings-win.data.microsoft.com"
	)
	edges := []connectivity.Edge{{
		IssuerIP:  issuer,
		DstIP:     dst,
		Protocol:  connectivity.ProtoTCP,
		Port:      443,
		FirstSeen: time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC),
	}}
	ipToDNS := map[string][]string{dst: {name}}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, ipToDNS, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	assertNoTopologyRowsWithDNSNameAndEmptySource(t, got)
	if got[0].DNSName != name || got[0].DNSSource != "csv+mid" {
		t.Fatalf("CSV fallback did not emit source: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixNormalizedRowsStillHaveSource(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, minimalDNSNormalizationRuleYAML("prod-ef.g2mobility.com"))
	got, audit := ApplyDNSNormalization("404163-1", []TopologyEntry{{
		IssuerIP:      "10.119.239.123",
		DestinationIP: "48.209.138.168",
		DNSName:       "prod-ef.g2mobility.com",
		DNSSource:     "dns+synack",
		Protocol:      "tcp",
		Port:          9999,
	}}, rules)
	if len(audit) != 1 {
		t.Fatalf("got %d audit rows, want 1: %#v", len(audit), audit)
	}
	assertNoTopologyRowsWithDNSNameAndEmptySource(t, got)
	if got[0].DNSName != "evse.total-ev-charge.com" || got[0].DNSSource != "dns+synack+norm" {
		t.Fatalf("normalized row did not retain source: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixAllowsDirectDNSAttributionForPrivateDestination(t *testing.T) {
	const (
		issuer = "10.119.239.123"
		dst    = "10.241.221.12"
		name   = "evse.total-ev-charge.com"
	)
	dnsTime := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	txs := []*DNSTransaction{{
		RequestTime:  dnsTime,
		IssuerIP:     net.ParseIP(issuer),
		DNSName:      name,
		ResolvedIPs:  []net.IP{net.ParseIP(dst)},
		NameEvidence: EvDNSAnswer,
		ResolvedIPEvidence: map[string]Evidence{
			dst: EvDNSAnswer,
		},
	}}
	edges := []connectivity.Edge{{
		IssuerIP:  issuer,
		DstIP:     dst,
		Protocol:  connectivity.ProtoTCP,
		Port:      9999,
		FirstSeen: dnsTime.Add(100 * time.Millisecond),
	}}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	row := got[0]
	if row.IssuerIP != issuer || row.DestinationIP != dst || row.Protocol != "tcp" || row.Port != 9999 {
		t.Fatalf("unexpected endpoint row: %#v", row)
	}
	if row.DNSName != name || row.DNSSource != "dns+synack" {
		t.Fatalf("private direct DNS attribution failed: %#v", row)
	}
}

func TestNetworkTopologyMatrixKeepsPrivateDestinationUnattributedWithoutDirectDNS(t *testing.T) {
	edges := []connectivity.Edge{{
		IssuerIP:  "10.119.239.123",
		DstIP:     "10.241.221.12",
		Protocol:  connectivity.ProtoTCP,
		Port:      9999,
		FirstSeen: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
	}}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, nil, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	if got[0].DNSName != "" || got[0].DNSSource != "" {
		t.Fatalf("private destination without direct DNS was attributed: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixDoesNotUseCSVFallbackForPrivateDestination(t *testing.T) {
	const dst = "10.241.221.12"
	edges := []connectivity.Edge{{
		IssuerIP:  "10.119.239.123",
		DstIP:     dst,
		Protocol:  connectivity.ProtoTCP,
		Port:      9999,
		FirstSeen: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
	}}
	ipToDNS := map[string][]string{
		dst: {"evse.total-ev-charge.com"},
	}

	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, ipToDNS, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	if got[0].DNSName != "" || got[0].DNSSource != "" {
		t.Fatalf("private destination used CSV fallback unexpectedly: %#v", got[0])
	}
}

func TestPrivateCSVFallbackStillDisabled(t *testing.T) {
	const dst = "10.241.221.12"
	got := BuildNetworkTopologyMatrixEntriesWithOptions(
		nil,
		[]connectivity.Edge{{
			IssuerIP:  "10.119.239.123",
			DstIP:     dst,
			Protocol:  connectivity.ProtoTCP,
			Port:      9999,
			FirstSeen: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
		}},
		nil,
		map[string][]string{dst: {"evse.total-ev-charge.com"}},
		DefaultTopologyBuildOptions(),
	)

	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	if got[0].DNSName != "" || got[0].DNSSource != "" {
		t.Fatalf("private destination used CSV fallback unexpectedly: %#v", got[0])
	}
}

func TestNetworkTopologyMatrixDoesNotDonateToPrivateDestination(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonation([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	})

	if got[1].DNSName != "" || got[1].DNSSource != "mid-session" {
		t.Fatalf("private destination received donation unexpectedly: %#v", got[1])
	}
}

func TestNetworkTopologyMatrixPrivateDonationRejectsWeakSourcesWhenEnabled(t *testing.T) {
	const dst = "10.241.221.12"
	for _, source := range []string{
		"dns+conn+synack",
		"csv+conn",
		"csv+mid",
		"active+matrix",
		"ptr+matrix",
		"tls-cert-san+matrix",
		"donated+ipport",
		"donated+ipport-private",
	} {
		t.Run(source, func(t *testing.T) {
			got := CompleteTopologyWithDNSDonationWithOptions([]TopologyEntry{
				{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "weak.example.com", DNSSource: source, Protocol: "tcp", Port: 9999},
				{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
			}, DNSDonationOptions{AllowPrivateDestinations: true})

			if got[1].DNSName != "" || got[1].DNSSource != "mid-session" {
				t.Fatalf("weak source %q donated to private destination unexpectedly: %#v", source, got[1])
			}
		})
	}
}

func TestDNSNormalizationAppliesToPrivateDirectDNSRow(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, minimalDNSNormalizationRuleYAML("prod-ef.g2mobility.com"))

	got, audit := ApplyDNSNormalization("404163-1", []TopologyEntry{{
		IssuerIP:      "10.119.239.123",
		DestinationIP: "10.241.221.12",
		DNSName:       "prod-ef.g2mobility.com",
		DNSSource:     "dns+synack",
		Protocol:      "tcp",
		Port:          9999,
	}}, rules)

	if len(audit) != 1 {
		t.Fatalf("got %d audit rows, want 1: %#v", len(audit), audit)
	}
	row := got[0]
	if row.DNSName != "evse.total-ev-charge.com" ||
		row.DNSSource != "dns+synack+norm" ||
		row.ObservedDNSName != "prod-ef.g2mobility.com" ||
		row.NormalizedDNSName != "evse.total-ev-charge.com" ||
		row.NormalizationRuleID != "dns_normalize_tcsevplatform_evse" {
		t.Fatalf("private direct DNS row was not normalized as expected: %#v", row)
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

func TestPrivateDonationDisabledByDefault(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonation([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	})

	if got[1].DNSName != "" || got[1].DNSSource != "mid-session" {
		t.Fatalf("private destination received donation by default: %#v", got[1])
	}
}

func TestPrivateDonationEnabledFromDirectDonor(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonationWithOptions([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	}, DNSDonationOptions{AllowPrivateDestinations: true})

	if got[1].DNSName != "evse.total-ev-charge.com" || got[1].DNSSource != "donated+ipport-private" {
		t.Fatalf("private destination was not donated from direct donor: %#v", got[1])
	}
}

func TestPrivateDonationEnabledFromNormalizedDirectDonor(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonationWithOptions([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack+norm", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	}, DNSDonationOptions{AllowPrivateDestinations: true})

	if got[1].DNSName != "evse.total-ev-charge.com" || got[1].DNSSource != "donated+ipport-private+norm" {
		t.Fatalf("private destination was not donated from normalized direct donor: %#v", got[1])
	}
}

func TestPrivateDonationDoesNotUseConnInferredDonor(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonationWithOptions([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+conn+synack", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	}, DNSDonationOptions{AllowPrivateDestinations: true})

	if got[1].DNSName != "" || got[1].DNSSource != "mid-session" {
		t.Fatalf("private destination received donation from conn-inferred donor: %#v", got[1])
	}
}

func TestPrivateDonationExactPortProtocolOnly(t *testing.T) {
	const dst = "10.241.221.12"
	got := CompleteTopologyWithDNSDonationWithOptions([]TopologyEntry{
		{IssuerIP: "10.119.239.124", DestinationIP: dst, DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999},
		{IssuerIP: "10.119.239.123", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.119.239.122", DestinationIP: dst, DNSName: "", DNSSource: "mid-session", Protocol: "udp", Port: 9999},
	}, DNSDonationOptions{AllowPrivateDestinations: true})

	for _, idx := range []int{1, 2} {
		if got[idx].DNSName != "" || got[idx].DNSSource != "mid-session" {
			t.Fatalf("private destination row %d received cross tuple donation: %#v", idx, got[idx])
		}
	}
}

func TestPublicDonationDefaultBehaviorUnchanged(t *testing.T) {
	got := CompleteTopologyWithDNSDonation([]TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "api.example.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.2", DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.3", DestinationIP: "1.1.1.1", DNSName: "norm.example.com", DNSSource: "dns+synack+norm", Protocol: "tcp", Port: 443},
		{IssuerIP: "10.0.0.4", DestinationIP: "1.1.1.1", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 443},
	})

	if got[1].DNSName != "api.example.com" || got[1].DNSSource != "donated+ipport" {
		t.Fatalf("public direct donation changed: %#v", got[1])
	}
	if got[3].DNSName != "norm.example.com" || got[3].DNSSource != "donated+ipport+norm" {
		t.Fatalf("public normalized donation changed: %#v", got[3])
	}
}

func TestNetworkTopologyMatrixCanAttributeEndpointSeenBeforeDNSWhenLaterObservationMatchesDNS(t *testing.T) {
	const (
		issuer = "10.118.216.226"
		dst    = "18.158.161.168"
		name   = "edge.platform.gridx.ai"
	)

	firstSeen := time.Date(2026, 7, 8, 0, 0, 42, 51_357_000, time.UTC)
	dnsTime := firstSeen.Add(2 * time.Minute)
	laterSyn := dnsTime.Add(500 * time.Millisecond)

	txs := []*DNSTransaction{
		{
			RequestTime:  dnsTime,
			IssuerIP:     net.ParseIP(issuer),
			DNSName:      name,
			ResolvedIPs:  []net.IP{net.ParseIP(dst)},
			NameEvidence: EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				dst: EvDNSAnswer,
			},
		},
	}
	edges := []connectivity.Edge{
		{
			IssuerIP:      issuer,
			DstIP:         dst,
			Protocol:      connectivity.ProtoTCP,
			Port:          443,
			FirstSeen:     firstSeen,
			ObservedTimes: []time.Time{firstSeen, laterSyn},
		},
	}

	opt := DefaultTopologyBuildOptions()
	opt.MaxDNSAge = time.Second
	got := BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, opt)

	if len(got) != 1 {
		t.Fatalf("expected one endpoint row, got %d: %#v", len(got), got)
	}
	row := got[0]
	if row.IssuerIP != issuer || row.DestinationIP != dst || row.Protocol != "tcp" || row.Port != 443 {
		t.Fatalf("unexpected endpoint row: %#v", row)
	}
	if row.DNSName != name || row.DNSSource != "dns+synack" {
		t.Fatalf("expected later observation to produce dns+synack attribution, got %#v", row)
	}
	if !row.ObservedAt.Equal(laterSyn) {
		t.Fatalf("expected observed_at to use DNS-matched later observation %s, got %s", laterSyn, row.ObservedAt)
	}
}

func TestNetworkTopologyMatrixUsesLaterObservationForMultiAResponse(t *testing.T) {
	const (
		issuer = "10.244.201.9"
		dst    = "3.64.65.68"
		otherA = "3.67.27.1"
		name   = "evse.total-ev-charge.com"
	)

	firstSeen := time.Date(2026, 7, 8, 0, 0, 32, 752_531_055, time.UTC)
	dnsTime := time.Date(2026, 7, 8, 0, 33, 34, 923_939_000, time.UTC)
	laterSyn := dnsTime.Add(121 * time.Millisecond)

	txs := []*DNSTransaction{
		{
			RequestTime:  dnsTime,
			IssuerIP:     net.ParseIP(issuer),
			DNSName:      name,
			ResolvedIPs:  []net.IP{net.ParseIP(dst), net.ParseIP(otherA)},
			NameEvidence: EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				dst:    EvDNSAnswer,
				otherA: EvDNSAnswer,
			},
		},
	}
	edges := []connectivity.Edge{
		{
			IssuerIP:      issuer,
			DstIP:         dst,
			Protocol:      connectivity.ProtoTCP,
			Port:          9999,
			FirstSeen:     firstSeen,
			ObservedTimes: []time.Time{firstSeen, laterSyn},
		},
	}

	opt := DefaultTopologyBuildOptions()
	opt.MaxDNSAge = 500 * time.Millisecond
	got := BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, opt)

	if len(got) != 1 {
		t.Fatalf("expected one endpoint row, got %d: %#v", len(got), got)
	}
	row := got[0]
	if row.IssuerIP != issuer || row.DestinationIP != dst || row.Protocol != "tcp" || row.Port != 9999 {
		t.Fatalf("unexpected endpoint row: %#v", row)
	}
	if row.DNSName != name || row.DNSSource != "dns+synack" {
		t.Fatalf("expected multi-A DNS response to match later observation, got %#v", row)
	}
	if !row.ObservedAt.Equal(laterSyn) {
		t.Fatalf("expected observed_at to use DNS-matched later observation %s, got %s", laterSyn, row.ObservedAt)
	}
}

func TestDNSAnswerDoesNotAttributeUnobservedPort(t *testing.T) {
	const (
		issuer = "10.245.214.104"
		dst    = "1.2.3.4"
		name   = "example.com"
	)
	dnsTime := time.Date(2026, 7, 11, 23, 35, 4, 400_000_000, time.UTC)
	t443 := dnsTime.Add(100 * time.Millisecond)
	t80 := dnsTime.Add(150 * time.Millisecond)
	p443 := uint16(443)

	tx := &DNSTransaction{
		RequestTime:     dnsTime,
		IssuerIP:        net.ParseIP(issuer),
		DNSName:         name,
		DestinationPort: &p443,
		ProtocolL4:      L4ProtoTCP,
		NameEvidence:    EvDNSAnswer,
		ResolvedIPEvidence: map[string]Evidence{
			dst: EvDNSAnswer | EvObservedConn,
		},
	}
	tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer|EvObservedConn)
	tx.AddObservedEndpointBinding(ObservedEndpointBinding{DstIP: dst, Protocol: L4ProtoTCP, Port: 443, ObservedAt: t443})

	edges := []connectivity.Edge{
		{IssuerIP: issuer, DstIP: dst, Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: t443, ObservedTimes: []time.Time{t443}},
		{IssuerIP: issuer, DstIP: dst, Protocol: connectivity.ProtoTCP, Port: 80, FirstSeen: t80, ObservedTimes: []time.Time{t80}},
	}

	got := BuildNetworkTopologyMatrixEntriesWithOptions([]*DNSTransaction{tx}, edges, nil, nil, DefaultTopologyBuildOptions())
	row443, ok := findTopologyRow(got, issuer, dst, "tcp", 443)
	if !ok || row443.DNSName != name || row443.DNSSource != "dns+synack" {
		t.Fatalf("tcp/443 row = %#v present=%v, want dns+synack; all rows %#v", row443, ok, got)
	}
	row80, ok := findTopologyRow(got, issuer, dst, "tcp", 80)
	if !ok {
		t.Fatalf("missing tcp/80 row; all rows %#v", got)
	}
	if row80.DNSSource == "dns+synack" {
		t.Fatalf("tcp/80 received direct DNS without observed binding: %#v", row80)
	}
}

func TestObservedBindingMustMatchEdgeObservationTime(t *testing.T) {
	const (
		issuer = "10.245.214.104"
		dst    = "1.2.3.4"
		name   = "example.com"
	)
	dnsTime := time.Date(2026, 7, 11, 23, 35, 4, 400_000_000, time.UTC)
	edgeTime := dnsTime.Add(100 * time.Millisecond)
	bindingTime := dnsTime.Add(200 * time.Millisecond)
	p443 := uint16(443)

	tx := &DNSTransaction{
		RequestTime:     dnsTime,
		IssuerIP:        net.ParseIP(issuer),
		DNSName:         name,
		DestinationPort: &p443,
		ProtocolL4:      L4ProtoTCP,
		NameEvidence:    EvDNSAnswer,
		ResolvedIPEvidence: map[string]Evidence{
			dst: EvDNSAnswer | EvObservedConn,
		},
	}
	tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer|EvObservedConn)
	tx.AddObservedEndpointBinding(ObservedEndpointBinding{DstIP: dst, Protocol: L4ProtoTCP, Port: 443, ObservedAt: bindingTime})

	got := BuildNetworkTopologyMatrixEntriesWithOptions(
		[]*DNSTransaction{tx},
		[]connectivity.Edge{{
			IssuerIP:      issuer,
			DstIP:         dst,
			Protocol:      connectivity.ProtoTCP,
			Port:          443,
			FirstSeen:     edgeTime,
			ObservedTimes: []time.Time{edgeTime},
		}},
		nil,
		nil,
		DefaultTopologyBuildOptions(),
	)

	row, ok := findTopologyRow(got, issuer, dst, "tcp", 443)
	if !ok {
		t.Fatalf("missing tcp/443 row; all rows %#v", got)
	}
	if row.DNSSource == "dns+synack" {
		t.Fatalf("edge was attributed from binding at a different timestamp: %#v", row)
	}
}

func TestMultipleDNSNamesSameIPDoNotCrossAttributePortsWithoutEvidence(t *testing.T) {
	const (
		issuer = "10.245.214.104"
		dst    = "1.2.3.4"
	)
	t0 := time.Date(2026, 7, 11, 23, 35, 4, 0, time.UTC)
	t1 := t0.Add(100 * time.Millisecond)
	t2 := t0.Add(2 * time.Second)
	t3 := t2.Add(100 * time.Millisecond)
	p443 := uint16(443)
	p80 := uint16(80)

	txA := &DNSTransaction{
		RequestTime:     t0,
		IssuerIP:        net.ParseIP(issuer),
		DNSName:         "a.example.com",
		DestinationPort: &p443,
		ProtocolL4:      L4ProtoTCP,
		NameEvidence:    EvDNSAnswer,
		ResolvedIPEvidence: map[string]Evidence{
			dst: EvDNSAnswer | EvObservedConn,
		},
	}
	txA.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer|EvObservedConn)
	txA.AddObservedEndpointBinding(ObservedEndpointBinding{DstIP: dst, Protocol: L4ProtoTCP, Port: 443, ObservedAt: t1})

	txB := &DNSTransaction{
		RequestTime:     t2,
		IssuerIP:        net.ParseIP(issuer),
		DNSName:         "b.example.com",
		DestinationPort: &p80,
		ProtocolL4:      L4ProtoTCP,
		NameEvidence:    EvDNSAnswer,
		ResolvedIPEvidence: map[string]Evidence{
			dst: EvDNSAnswer | EvObservedConn,
		},
	}
	txB.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer|EvObservedConn)
	txB.AddObservedEndpointBinding(ObservedEndpointBinding{DstIP: dst, Protocol: L4ProtoTCP, Port: 80, ObservedAt: t3})

	opt := DefaultTopologyBuildOptions()
	opt.MaxDNSAge = 5 * time.Second
	got := BuildNetworkTopologyMatrixEntriesWithOptions(
		[]*DNSTransaction{txA, txB},
		[]connectivity.Edge{
			{IssuerIP: issuer, DstIP: dst, Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: t1, ObservedTimes: []time.Time{t1}},
			{IssuerIP: issuer, DstIP: dst, Protocol: connectivity.ProtoTCP, Port: 80, FirstSeen: t3, ObservedTimes: []time.Time{t3}},
		},
		nil,
		nil,
		opt,
	)

	row443, ok := findTopologyRow(got, issuer, dst, "tcp", 443)
	if !ok || row443.DNSName != "a.example.com" || row443.DNSSource != "dns+synack" {
		t.Fatalf("tcp/443 row = %#v present=%v, want a.example.com dns+synack; all rows %#v", row443, ok, got)
	}
	row80, ok := findTopologyRow(got, issuer, dst, "tcp", 80)
	if !ok || row80.DNSName != "b.example.com" || row80.DNSSource != "dns+synack" {
		t.Fatalf("tcp/80 row = %#v present=%v, want b.example.com dns+synack; all rows %#v", row80, ok, got)
	}
}

func TestLegacyDestinationPortStillPopulatesDNSOutput(t *testing.T) {
	p443 := uint16(443)
	tx := &DNSTransaction{
		RequestTime:     time.Date(2026, 7, 11, 23, 35, 4, 0, time.UTC),
		IssuerIP:        net.ParseIP("10.245.214.104"),
		DNSName:         "time.samsungcloudsolution.com",
		DestinationPort: &p443,
		ProtocolL4:      L4ProtoTCP,
		NameEvidence:    EvDNSAnswer,
	}
	tx.AddResolvedIP(net.ParseIP("23.97.174.104"), EvDNSAnswer|EvObservedConn)
	tx.AddObservedEndpointBinding(ObservedEndpointBinding{
		DstIP:      "23.97.174.104",
		Protocol:   L4ProtoTCP,
		Port:       80,
		ObservedAt: tx.RequestTime.Add(200 * time.Millisecond),
	})

	records := ToOutputRecords([]*DNSTransaction{tx})
	if len(records) != 1 {
		t.Fatalf("ToOutputRecords produced %d records: %#v", len(records), records)
	}
	if records[0].DestinationPort == nil || *records[0].DestinationPort != 443 {
		t.Fatalf("legacy destination_port = %#v, want 443", records[0].DestinationPort)
	}
}

func TestObservedEndpointBindingsSurviveTransactionMerge(t *testing.T) {
	requestTime := time.Date(2026, 7, 11, 23, 35, 4, 0, time.UTC)
	txA := &DNSTransaction{RequestTime: requestTime, IssuerIP: net.ParseIP("10.245.214.104"), DNSName: "example.com"}
	txA.AddObservedEndpointBinding(ObservedEndpointBinding{
		DstIP:      "1.2.3.4",
		Protocol:   L4ProtoTCP,
		Port:       443,
		ObservedAt: requestTime.Add(100 * time.Millisecond),
	})
	txB := &DNSTransaction{RequestTime: requestTime, IssuerIP: net.ParseIP("10.245.214.104"), DNSName: "example.com"}
	txB.AddObservedEndpointBinding(ObservedEndpointBinding{
		DstIP:      "1.2.3.4",
		Protocol:   L4ProtoTCP,
		Port:       443,
		ObservedAt: requestTime.Add(100 * time.Millisecond),
	})
	txB.AddObservedEndpointBinding(ObservedEndpointBinding{
		DstIP:      "1.2.3.4",
		Protocol:   L4ProtoTCP,
		Port:       80,
		ObservedAt: requestTime.Add(200 * time.Millisecond),
	})

	bucket := mergeDNSTransactionIntoBucket([]*DNSTransaction{txA}, txB)
	if len(bucket) != 1 {
		t.Fatalf("merge bucket len = %d, want 1", len(bucket))
	}
	if got := len(bucket[0].ObservedEndpointBindings); got != 2 {
		t.Fatalf("merged bindings len = %d, want 2: %#v", got, bucket[0].ObservedEndpointBindings)
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
		{name: "DNS connection inferred normalized", source: " DNS+CONN+SYNACK ", want: dnsDonationDonorNone},
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
			name:       "E single inferred name cannot donate",
			donors:     []TopologyEntry{{DestinationIP: ip, DNSName: "inferred.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port}},
			wantSource: "mid-session",
		},
		{
			name: "F multiple inferred names cannot donate",
			donors: []TopologyEntry{
				{DestinationIP: ip, DNSName: "one.service.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
				{DestinationIP: ip, DNSName: "two.service.example.com", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
			},
			wantSource: "mid-session",
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
		t.Fatalf("CSV attribution was unexpectedly upgraded by exact donation: %#v", got[4])
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
		"tls-cert-san+matrix-fallback",
		"active",
		"active+synack",
		"active+matrix",
		"peer+ipport",
		"peer+ipport+conn",
		"donated+ipport",
		"donated+ipport+conn",
		"donated+ipport-private",
		"donated+ipport-private+norm",
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

func TestCompleteTopologyWithDNSDonationDoesNotUseUniqueInferredDonor(t *testing.T) {
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

	var foundDonor, foundUncompletedPeer bool
	for _, row := range out {
		if row.IssuerIP == "10.116.12.67" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "a3ikz8tra5nexo.iot.ap-southeast-2.amazonaws.c" || row.DNSSource != "dns+conn+synack" {
				t.Fatalf("inferred donor row changed unexpectedly: %#v", row)
			}
			foundDonor = true
		}
		if row.IssuerIP == "10.116.12.7" && row.DestinationIP == "13.55.209.128" && row.Port == 8883 {
			if row.DNSName != "" || row.DNSSource != "mid-session" {
				t.Fatalf("inferred donor completed peer row unexpectedly: %#v", row)
			}
			foundUncompletedPeer = true
		}
	}
	if !foundDonor || !foundUncompletedPeer {
		t.Fatalf("expected unchanged donor and uncompleted peer; got %#v", out)
	}
}

func TestCompleteTopologyWithDNSDonationRejectsInferredDonationOnExactDestination(t *testing.T) {
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

	donors, unresolvedPeers := 0, 0
	for _, row := range out {
		switch {
		case row.DNSSource == "dns+conn+synack":
			if row.DNSName != "www.cisco.com" {
				t.Fatalf("unexpected inferred donor name: %#v", row)
			}
			donors++
		case row.DNSSource == "mid-session" && row.DNSName == "":
			unresolvedPeers++
		default:
			t.Fatalf("unexpected row source: %#v", row)
		}
	}
	if donors != 2 || unresolvedPeers != 2 {
		t.Fatalf("donors=%d unresolved_peers=%d, want 2 each; out=%#v", donors, unresolvedPeers, out)
	}
}

func TestCompleteTopologyWithDNSDonationDirectDonorStillDonatesWhenInferredPresent(t *testing.T) {
	const (
		ip    = "8.8.8.8"
		proto = "tcp"
		port  = uint16(443)
	)

	got := CompleteTopologyWithDNSDonation([]TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: ip, DNSName: "direct.example.com", DNSSource: "dns+synack", Protocol: proto, Port: port},
		{IssuerIP: "10.0.0.2", DestinationIP: ip, DNSName: "inferred.example.net", DNSSource: "dns+conn+synack", Protocol: proto, Port: port},
		{IssuerIP: "10.0.0.3", DestinationIP: ip, DNSSource: "mid-session", Protocol: proto, Port: port},
	})

	if got[2].DNSName != "direct.example.com" || got[2].DNSSource != "donated+ipport" {
		t.Fatalf("direct donor did not complete peer row while inferred donor was present: %#v", got)
	}
	if got[1].DNSName != "inferred.example.net" || got[1].DNSSource != "dns+conn+synack" {
		t.Fatalf("inferred donor row was mutated: %#v", got)
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
