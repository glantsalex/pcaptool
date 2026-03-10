package dns

import (
	"net"
	"testing"
	"time"
)

func TestBuildIPDNSAppendAuditRecords_UsesEarliestStrongMatch(t *testing.T) {
	t1 := time.Date(2026, 3, 8, 8, 0, 0, 0, time.UTC)
	t2 := t1.Add(2 * time.Minute)
	port80 := uint16(80)

	txs := []*DNSTransaction{
		{
			RequestTime:     t2,
			IssuerIP:        net.ParseIP("10.0.0.2"),
			DNSName:         "ocppj.freshmile.com",
			ResolvedIPs:     []net.IP{net.ParseIP("4.178.249.19")},
			ResolverIP:      net.ParseIP("8.8.8.8"),
			DestinationPort: &port80,
			ProtocolL4:      L4ProtoTCP,
			PCAPFile:        "b.pcap",
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"4.178.249.19": EvDNSAnswer | EvObservedConn,
			},
		},
		{
			RequestTime:     t1,
			IssuerIP:        net.ParseIP("10.0.0.1"),
			DNSName:         "ocppj.freshmile.com.",
			ResolvedIPs:     []net.IP{net.ParseIP("4.178.249.19")},
			ResolverIP:      net.ParseIP("1.1.1.1"),
			DestinationPort: &port80,
			ProtocolL4:      L4ProtoTCP,
			PCAPFile:        "a.pcap",
			NameEvidence:    EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"4.178.249.19": EvDNSAnswer | EvObservedConn,
			},
		},
		{
			RequestTime:  t1.Add(1 * time.Minute),
			IssuerIP:     net.ParseIP("10.0.0.3"),
			DNSName:      "weak.example.com",
			ResolvedIPs:  []net.IP{net.ParseIP("20.20.20.20")},
			NameEvidence: EvDNSAnswer,
			ResolvedIPEvidence: map[string]Evidence{
				"20.20.20.20": EvDNSAnswer,
			},
		},
	}

	got := BuildIPDNSAppendAuditRecords(txs, []IPDNSPair{
		{DNS: "ocppj.freshmile.com", IP: "4.178.249.19"},
		{DNS: "weak.example.com", IP: "20.20.20.20"},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(got))
	}

	if got[0].DNS != "ocppj.freshmile.com" || got[0].IP != "4.178.249.19" {
		t.Fatalf("unexpected first row: %+v", got[0])
	}
	if got[0].IssuerIP != "10.0.0.1" {
		t.Fatalf("expected earliest issuer IP, got %+v", got[0])
	}
	if got[0].ResolverIP != "1.1.1.1" || got[0].PCAPFile != "a.pcap" {
		t.Fatalf("expected earliest provenance, got %+v", got[0])
	}
	if got[0].Evidence != "dns+synack" {
		t.Fatalf("expected strong evidence label, got %+v", got[0])
	}

	if got[1].DNS != "weak.example.com" || got[1].IP != "20.20.20.20" {
		t.Fatalf("unexpected fallback row: %+v", got[1])
	}
	if got[1].IssuerIP != "" || got[1].Evidence != "" {
		t.Fatalf("expected empty provenance for non-strong pair, got %+v", got[1])
	}
}
