package dns

import (
	"net"
	"testing"
)

func TestComputeUnresolvedDNSFirstSeen_DecisionByNameNotIssuer(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")

	txs := []*DNSTransaction{
		{DNSName: "foo.example.com", IssuerIP: ipA, PCAPFile: "a.pcap"},
		{DNSName: "foo.example.com", IssuerIP: ipB, PCAPFile: "b.pcap"},
		{
			DNSName:     "foo.example.com",
			IssuerIP:    ipA,
			PCAPFile:    "c.pcap",
			ResolvedIPs: []net.IP{net.ParseIP("8.8.8.8")},
		},
		{DNSName: "bar.example.com", IssuerIP: ipA, PCAPFile: "d.pcap"},
	}

	got := ComputeUnresolvedDNSFirstSeen(txs)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d, want 1", len(got))
	}

	if got[0].Name != "bar.example.com" {
		t.Fatalf("name=%q, want bar.example.com", got[0].Name)
	}
	if got[0].IssuerIP != "10.0.0.1" || got[0].FirstPCAPFile != "d.pcap" {
		t.Fatalf("row unexpected: %#v", got[0])
	}
}

func TestFilterUnresolvedByTopologyAttribution_IgnoresIssuer(t *testing.T) {
	unresolved := []DNSUnresolvedStat{
		{Name: "siconfig.ep2.telekurs.com", IssuerIP: "10.245.254.248", FirstPCAPFile: "a.pcap"},
		{Name: "keep.example.com", IssuerIP: "10.245.254.248", FirstPCAPFile: "b.pcap"},
	}

	topo := []TopologyEntry{
		{
			IssuerIP:      "10.245.99.1",
			DestinationIP: "153.46.253.155",
			DNSName:       "siconfig.ep2.telekurs.com",
			DNSSource:     "csv+mid",
			Protocol:      "tcp",
			Port:          8115,
		},
	}

	got := FilterUnresolvedByTopologyAttribution(unresolved, topo)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d, want 1; got=%#v", len(got), got)
	}
	if got[0].Name != "keep.example.com" {
		t.Fatalf("unexpected remaining unresolved row: %#v", got[0])
	}
}

func TestFilterUnresolvedByTruncatedDNSPacketsExactCanonicalMatch(t *testing.T) {
	unresolved := []DNSUnresolvedStat{
		{Name: "API.EXAMPL.", IssuerIP: "10.0.0.1", FirstPCAPFile: "a.pcap"},
		{Name: "api.example.com", IssuerIP: "10.0.0.1", FirstPCAPFile: "b.pcap"},
		{Name: "normal.example", IssuerIP: "10.0.0.2", FirstPCAPFile: "c.pcap"},
	}
	truncated := []TruncatedDNSPacket{
		{TruncatedDNSName: "api.exampl"},
		{TruncatedDNSName: " API.EXAMPL. "},
	}

	got := FilterUnresolvedByTruncatedDNSPackets(unresolved, truncated)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2; got = %#v", len(got), got)
	}
	if got[0].Name != "api.example.com" || got[1].Name != "normal.example" {
		t.Fatalf("unexpected remaining unresolved rows: %#v", got)
	}
}
