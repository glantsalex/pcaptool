package dns

import (
	"reflect"
	"testing"
)

func TestFreshIPDonationUpgradesCSVAcrossIssuerAndPort(t *testing.T) {
	got := CompleteTopologyWithFreshIPDNSDonation([]TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "cached.example", "csv+mid", "tcp", 443),
	})

	assertFreshIPDonationRow(t, got[1], "foo.bar.com", "donated+ip")
}

func TestFreshIPDonationFillsMidSessionAcrossIssuerAndPort(t *testing.T) {
	got := CompleteTopologyWithFreshIPDNSDonation([]TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 443),
	})

	assertFreshIPDonationRow(t, got[1], "foo.bar.com", "donated+ip")
}

func TestFreshIPDonationReplacesConflictingHistoricalCSV(t *testing.T) {
	got := CompleteTopologyWithFreshIPDNSDonation([]TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "stale.example.com", "csv+conn", "udp", 443),
	})

	assertFreshIPDonationRow(t, got[1], "foo.bar.com", "donated+ip")
}

func TestFreshIPDonationDoesNotRunForAmbiguousIP(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.3", "1.2.3.4", "api.other.net", "dns+synack", "tcp", 8443),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "cached.example", "csv+mid", "tcp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("ambiguous IP donation changed rows:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationAllowsUniqueNormalizedIdentity(t *testing.T) {
	got := CompleteTopologyWithFreshIPDNSDonation([]TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "evse.total-ev-charge.com", "dns+synack+norm", "tcp", 9999),
		freshIPDonationRow("10.0.0.3", "1.2.3.4", "evse.total-ev-charge.com", "dns+synack+norm", "tcp", 443),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 80),
	})

	assertFreshIPDonationRow(t, got[2], "evse.total-ev-charge.com", "donated+ip+norm")
}

func TestFreshIPDonationMarksNormalizedParticipation(t *testing.T) {
	got := CompleteTopologyWithFreshIPDNSDonation([]TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "evse.total-ev-charge.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.3", "1.2.3.4", "evse.total-ev-charge.com", "dns+synack+norm", "tcp", 443),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 80),
	})

	assertFreshIPDonationRow(t, got[2], "evse.total-ev-charge.com", "donated+ip+norm")
}

func TestFreshIPDonationDoesNotUseExistingDonationAsDonor(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "donated+ipport", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 443),
		freshIPDonationRow("10.0.0.3", "1.2.3.5", "foo.bar.com", "donated+ip", "tcp", 9999),
		freshIPDonationRow("10.0.0.4", "1.2.3.5", "", "mid-session", "tcp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("existing donation acted as donor:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationDoesNotUseCSVAsDonor(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "csv+mid", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 443),
		freshIPDonationRow("10.0.0.3", "1.2.3.5", "foo.bar.com", "csv+conn", "tcp", 9999),
		freshIPDonationRow("10.0.0.4", "1.2.3.5", "", "mid-session", "tcp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("CSV row acted as donor:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationDoesNotOverwriteExactEndpointDonation(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "foo.bar.com", "donated+ipport", "tcp", 443),
		freshIPDonationRow("10.0.0.3", "1.2.3.4", "foo.bar.com", "donated+ipport+norm", "udp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("exact endpoint donation was overwritten:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationDoesNotOverwriteDirectDNS(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "foo.bar.com", "dns+synack+norm", "tcp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("direct DNS was overwritten:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationIsPublicOnly(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "10.0.0.10", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "10.0.0.10", "", "mid-session", "tcp", 443),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("private destination received IP-level donation:\n got %#v\nwant %#v", got, in)
	}
}

func TestFreshIPDonationIsDeterministic(t *testing.T) {
	a := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "FOO.Bar.Com.", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "", "mid-session", "tcp", 443),
		freshIPDonationRow("10.0.0.3", "1.2.3.5", "other.example.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.4", "1.2.3.5", "", "mid-session", "tcp", 443),
	}
	b := []TopologyEntry{a[2], a[3], a[0], a[1]}

	gotA := CompleteTopologyWithFreshIPDNSDonation(a)
	gotB := CompleteTopologyWithFreshIPDNSDonation(b)

	byIssuerA := freshIPDonationRowsByIssuer(gotA)
	byIssuerB := freshIPDonationRowsByIssuer(gotB)
	if !reflect.DeepEqual(byIssuerA["10.0.0.2"], byIssuerB["10.0.0.2"]) ||
		!reflect.DeepEqual(byIssuerA["10.0.0.4"], byIssuerB["10.0.0.4"]) {
		t.Fatalf("donation results differ by order:\nA %#v\nB %#v", byIssuerA, byIssuerB)
	}
}

func TestFreshIPDonationDoesNotUseMajorityVoting(t *testing.T) {
	in := []TopologyEntry{
		freshIPDonationRow("10.0.0.1", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 9999),
		freshIPDonationRow("10.0.0.2", "1.2.3.4", "foo.bar.com", "dns+synack", "tcp", 8443),
		freshIPDonationRow("10.0.0.3", "1.2.3.4", "other.example.com", "dns+synack", "tcp", 443),
		freshIPDonationRow("10.0.0.4", "1.2.3.4", "cached.example", "csv+mid", "tcp", 80),
	}
	got := CompleteTopologyWithFreshIPDNSDonation(in)

	if !reflect.DeepEqual(got, in) {
		t.Fatalf("majority voting changed ambiguous rows:\n got %#v\nwant %#v", got, in)
	}
}

func TestTopologySourceRankOrdersFreshIPDonationAboveCSVBelowExactDonation(t *testing.T) {
	if topologySourceRank("donated+ipport") <= topologySourceRank("donated+ip") {
		t.Fatalf("donated+ipport rank=%d, donated+ip rank=%d", topologySourceRank("donated+ipport"), topologySourceRank("donated+ip"))
	}
	if topologySourceRank("donated+ip") <= topologySourceRank("csv+mid") {
		t.Fatalf("donated+ip rank=%d, csv+mid rank=%d", topologySourceRank("donated+ip"), topologySourceRank("csv+mid"))
	}
	if topologySourceRank("donated+ip+norm") <= topologySourceRank("csv+conn") {
		t.Fatalf("donated+ip+norm rank=%d, csv+conn rank=%d", topologySourceRank("donated+ip+norm"), topologySourceRank("csv+conn"))
	}
	if topologySourceRank("dns+synack") <= topologySourceRank("donated+ipport") {
		t.Fatalf("dns+synack rank=%d, donated+ipport rank=%d", topologySourceRank("dns+synack"), topologySourceRank("donated+ipport"))
	}
}

func freshIPDonationRow(issuer, dst, name, source, proto string, port uint16) TopologyEntry {
	return TopologyEntry{
		IssuerIP:      issuer,
		DestinationIP: dst,
		DNSName:       name,
		DNSSource:     source,
		Protocol:      proto,
		Port:          port,
	}
}

func assertFreshIPDonationRow(t *testing.T, row TopologyEntry, wantName, wantSource string) {
	t.Helper()
	if row.DNSName != wantName || row.DNSSource != wantSource {
		t.Fatalf("row DNS/source = %q/%q, want %q/%q; row=%#v", row.DNSName, row.DNSSource, wantName, wantSource, row)
	}
}

func freshIPDonationRowsByIssuer(rows []TopologyEntry) map[string]TopologyEntry {
	out := make(map[string]TopologyEntry, len(rows))
	for _, row := range rows {
		out[row.IssuerIP] = row
	}
	return out
}
