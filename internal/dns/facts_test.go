package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestFactAnswerValidityAndOwnership(t *testing.T) {
	base := time.Unix(1700000000, 0)
	c := NewFactCollection(nil, false, 3*time.Second)
	first := net.IP{203, 0, 113, 1}
	second := net.IP{203, 0, 113, 2}
	event := func(sec int, name string, ip net.IP) {
		c.answer("A", name, base.Add(time.Second*time.Duration(sec)), []net.IP{ip}, nil, true)
	}
	event(5, "a.example", second)
	event(1, "a.example", first)
	event(2, "a.example", first)
	event(3, "b.example", first)
	event(6, "c.example", second)
	event(6, "d.example", second)
	first[3] = 99
	second[3] = 98
	c.Prepare(nil, nil, false)
	for _, tc := range []struct {
		sec        int
		addr, name string
	}{{0, "203.0.113.1", ""}, {1, "203.0.113.1", "a.example"}, {3, "203.0.113.1", "b.example"}, {7, "203.0.113.1", ""}, {5, "203.0.113.2", "a.example"}, {6, "203.0.113.2", ""}} {
		s := make(factSet)
		c.contact(s, make(provisionalFacts), "A", "10.0.0.1", tc.addr, connectivity.ProtoTCP, 443, base.Add(time.Duration(tc.sec)*time.Second), false)
		k := transportFact{"A", netip.MustParseAddr(tc.addr), connectivity.ProtoTCP, 443}
		if g, ok := s[k]; !ok || g.name != tc.name {
			t.Fatalf("%+v: got %+v", tc, g)
		}
	}
	if n := len(c.bindings[destinationKey{"A", netip.MustParseAddr("203.0.113.1")}]); n != 2 {
		t.Fatalf("repeated answers retained %d intervals, want 2", n)
	}
	if c.answers != nil {
		t.Fatal("answer build state retained after Prepare")
	}
	c.Take(30000, nil)
	if c.bindings != nil || c.facts != nil || c.unanswered != nil {
		t.Fatal("connection state retained after Take")
	}
}

func TestClientHelloFactOwnsPacketData(t *testing.T) {
	raw := buildSNIAdmissionPacket(t, "Owned.Example.", "10.0.0.1", "203.0.113.10")
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.NoCopy)
	packet.Metadata().Timestamp = time.Date(2399, 1, 1, 1, 0, 0, 123, time.UTC)
	c := NewFactCollection(func(netip.Addr, time.Time) string { return "A" }, true, 0)
	collector := connectivity.NewCollector(connectivity.DefaultOptions())
	if !c.hello(c.facts, packet, nil, collector) {
		t.Fatal("missing direct ClientHello")
	}
	clear(raw)
	rows := c.Take(30000, nil)
	if len(rows) != 1 || rows[0].DNSName != "owned.example" || rows[0].DestinationIP != "203.0.113.10" || !rows[0].ObservedAt.Equal(packet.Metadata().Timestamp) {
		t.Fatalf("retained packet memory or lost timestamp: %+v", rows)
	}
}
func TestFactsDonationAndReassignment(t *testing.T) {
	rows := []TopologyEntry{
		{IssuerIP: "A", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{IssuerIP: "A", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "sni", DNSName: "a.example"},
		{IssuerIP: "A", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "sni", DNSName: "b.example"},
		{IssuerIP: "B", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
	}
	rows = append(rows, TopologyEntry{IssuerIP: "A", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 8443})
	got := UniqueFacts(rows)
	if len(got) != 4 || got[0].DNSName != "a.example" || got[1].DNSName != "b.example" || got[2].DNSName != "" || got[3].DNSName != "" {
		t.Fatalf("incorrect donation scope %+v", got)
	}
}

func TestDNSCorroborationSurvivesDirectHello(t *testing.T) {
	k := factKey{transportFact{"A", netip.MustParseAddr("8.8.8.8"), connectivity.ProtoTCP, 443}, "a.example"}
	for _, sources := range [][]string{{"sni", "dns+synack"}, {"dns+synack", "sni"}} {
		s := make(factSet)
		for _, src := range sources {
			s.add(k, factValue{source: src})
		}
		if got := s[k.transportFact].value.source; got != "dns+synack" {
			t.Fatalf("cache/normalization lost DNS evidence: %s", got)
		}
	}
}

func TestNegativeAndPartialAnswers(t *testing.T) {
	c := NewFactCollection(nil, false, 0)
	ip := net.IPv4(8, 8, 8, 8)
	event := func(sec int64, ips []net.IP, complete bool) {
		c.answer("A", "dns.example", time.Unix(sec, 0), ips, nil, complete)
	}
	event(4, nil, true)
	event(1, []net.IP{ip}, true)
	event(2, []net.IP{net.IPv4(8, 8, 4, 4)}, false)
	c.Prepare(nil, nil, false)
	for _, dst := range []string{"8.8.8.8", "8.8.4.4"} {
		s := make(factSet)
		c.contact(s, make(provisionalFacts), "A", "10.0.0.1", dst, connectivity.ProtoTCP, 443, time.Unix(3, 0), false)
		c.contact(s, make(provisionalFacts), "A", "10.0.0.1", dst, connectivity.ProtoTCP, 8443, time.Unix(4, 0), false)
		if s[transportFact{"A", netip.MustParseAddr(dst), connectivity.ProtoTCP, 443}].name != "dns.example" || s[transportFact{"A", netip.MustParseAddr(dst), connectivity.ProtoTCP, 8443}].name != "" {
			t.Fatalf("invalid DNS validity: %+v", s)
		}
	}
}

func TestFactScanFailureReleasesPartialState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx      context.Context
		canceled bool
	}{{ctx, true}, {context.Background(), false}} {
		c := NewFactCollection(nil, true, 0)
		c.Prepare(nil, nil, false)
		_, _, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(tc.ctx, []string{filepath.Join(t.TempDir(), "missing.pcap")}, nil, false, false, nil, true, nil, nil, 0, PacketScanOptions{Facts: c})
		if err == nil || errors.Is(err, context.Canceled) != tc.canceled || c.bindings != nil || c.facts != nil {
			t.Fatalf("invalid partial result on failure: %+v %v", c, err)
		}
	}
}

func TestActiveNameRequiresQueryByContactingDevice(t *testing.T) {
	rows := []TopologyEntry{}
	for _, id := range []string{"A", "B", "C", "D"} {
		rows = append(rows, TopologyEntry{IssuerIP: id, DestinationIP: "8.8.8.8", Port: 443, Protocol: "tcp", ObservedAt: time.Unix(100, 0)})
	}
	txs := []*DNSTransaction{{IssuerLabel: "D", DNSName: "a.example", RequestTime: time.Unix(1, 0)}, {IssuerLabel: "A", DNSName: "a.example", RequestTime: time.Unix(97, 0)}, {IssuerLabel: "C", DNSName: "a.example", RequestTime: time.Unix(101, 0)}}
	got := CompleteFactsWithActiveDNS(rows, []DNSNameIPv4Resolution{{DNSName: "a.example", IPv4s: []string{"8.8.8.8"}}}, txs, 10*time.Second)
	if got[0].DNSName != "a.example" || got[1].DNSName != "" || got[2].DNSName != "" || got[3].DNSName != "" {
		t.Fatalf("active attribution escaped temporal device scope: %+v", got)
	}
}

func TestAmbiguousDNSBlocksIssuerOnlyInference(t *testing.T) {
	c := NewFactCollection(nil, false, time.Minute)
	ts := time.Unix(100, 0)
	for _, name := range []string{"one.example", "two.example"} {
		c.answer("A", name, ts, []net.IP{net.IPv4(8, 8, 8, 8)}, nil, true)
	}
	c.Prepare([]*DNSTransaction{{IssuerLabel: "A", DNSName: "wrong.example", RequestTime: ts}}, nil, true)
	s := make(factSet)
	c.contact(s, make(provisionalFacts), "A", "10.0.0.1", "8.8.8.8", connectivity.ProtoTCP, 443, ts, true)
	if group := s[transportFact{"A", netip.MustParseAddr("8.8.8.8"), connectivity.ProtoTCP, 443}]; group.name != "" {
		t.Fatalf("attributed ambiguous answer: %+v", group)
	}
}
