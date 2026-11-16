package dns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestSNIDedupRetainsTimeAndStableProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/testdata/radius-subnets.pcap")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a, b := filepath.Join(root, "a.pcap"), filepath.Join(root, "b.pcap")
	for _, f := range []string{a, b} {
		if err := os.WriteFile(f, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	var reference []time.Time
	for _, procs := range []int{1, 2, 8} {
		runtime.GOMAXPROCS(procs)
		for _, files := range [][]string{{a, b}, {b, a}} {
			txs, _, err := BuildTransactionsWithSNIFromPCAPs(context.Background(), files, true)
			if err != nil {
				t.Fatal(err)
			}
			var got []time.Time
			for _, tx := range txs {
				if tx.DNSName == "reused.example.test" {
					got = append(got, tx.RequestTime)
					if tx.PCAPFile != "a.pcap" {
						t.Fatalf("unstable provenance: %s", tx.PCAPFile)
					}
				}
			}
			if len(got) != 4 {
				t.Fatalf("timed observations=%v, want 4", got)
			}
			if reference == nil {
				reference = got
			} else if !reflect.DeepEqual(reference, got) {
				t.Fatal("timed SNI depends on file/worker order")
			}
		}
	}
}

func TestSNIDedupUsesFullTimestampPrecision(t *testing.T) {
	f, err := os.Open("../../cmd/testdata/radius-subnets.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	source := gopacket.NewPacketSource(reader, layers.LayerTypeEthernet)
	for pkt := range source.Packets() {
		extractor := newSNIExtractor()
		extractor.OnPacket(pkt, "test.pcap")
		if len(extractor.Slice()) == 0 {
			continue
		}
		at := pkt.Metadata().Timestamp
		extractor.OnPacket(pkt, "test.pcap") // exact copy collapses
		pkt.Metadata().Timestamp = at.Add(time.Nanosecond)
		extractor.OnPacket(pkt, "test.pcap")
		if len(extractor.Slice()) != 2 {
			t.Fatal("nanosecond observation was lost or exact duplicate survived")
		}
		return
	}
	t.Fatal("fixture contains no SNI")
}

func TestTopologyScopedIdentityDoesNotBorrowName(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	const ip = "10.1.1.1"
	resolve := func(_ string, at time.Time) string {
		if at.Before(base.Add(time.Second)) {
			return "A"
		}
		if at.Before(base.Add(2 * time.Second)) {
			return "B"
		}
		return ip
	}
	port := uint16(443)
	tx := &DNSTransaction{RequestTime: base, IssuerIP: net.ParseIP(ip), DNSName: "a.example.test", NameEvidence: EvSNI, DestinationPort: &port, ProtocolL4: L4ProtoTCP}
	tx.AddResolvedIP(net.ParseIP("203.0.113.1"), EvSNI|EvObservedConn)
	var edges []connectivity.Edge
	for i, id := range []string{"A", "B", ip} {
		edges = append(edges, connectivity.Edge{IssuerIP: ip, IssuerIdentity: id, DstIP: "203.0.113.1", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: base.Add(time.Duration(i) * time.Second)})
	}
	rows := BuildNetworkTopologyMatrixEntries([]*DNSTransaction{tx}, edges, resolve, nil)
	if len(rows) != 3 {
		t.Fatalf("rows=%+v", rows)
	}
	for _, row := range rows {
		if row.IssuerIP == "A" {
			if row.DNSName != "a.example.test" {
				t.Fatal(row)
			}
		} else if row.DNSName != "" {
			t.Fatalf("borrowed previous owner's SNI: %+v", row)
		}
	}
}

func TestIdentitySurvivesGlobalEdgeMergeAndSummarizesDeviceService(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	// Separate per-file edges share a raw IP but must not share their time budget.
	acc := newEdgeAccumulator()
	for i := 0; i < 300; i++ {
		id := "A"
		if i == 1 {
			id = "B"
		}
		if i > 1 {
			id = "C"
		}
		acc.merge([]connectivity.Edge{{IssuerIP: "10.1.1.1", IssuerIdentity: id, DstIP: "203.0.113.1", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: base.Add(time.Duration(i) * time.Second)}})
	}
	if len(acc.edges()) != 3 {
		t.Fatal("global merge discarded an identity")
	}
	// The same IMSI on another IP remains one final device/service row.
	acc.merge([]connectivity.Edge{{IssuerIP: "10.1.1.2", IssuerIdentity: "A", DstIP: "203.0.113.1", Protocol: connectivity.ProtoTCP, Port: 443, FirstSeen: base.Add(time.Hour)}})
	rows := BuildNetworkTopologyMatrixEntries(nil, acc.edges(), nil, nil)
	if len(rows) != 3 {
		t.Fatalf("rows=%+v", rows)
	}
	for _, row := range rows {
		if row.IssuerIP == "A" && !row.ObservedAt.Equal(base) {
			t.Fatal("summary lost earliest equal-rank observation")
		}
	}
}

func TestConnectionCorrelationRejectsPreviousIdentity(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	const issuer = "10.1.1.1"
	const dst = "203.0.113.1"
	path := filepath.Join(t.TempDir(), "reassigned.pcap")
	writeConnectionAdmissionPCAP(t, path, []dnsAdmissionPacket{{ts: base.Add(time.Second), data: buildConnectionInferenceTestTCPPacket(t, issuer, dst, 40000, 443, true, false)}})
	for _, scoped := range []bool{false, true} {
		tx := &DNSTransaction{RequestTime: base, IssuerIP: net.ParseIP(issuer), DNSName: "a.example.test", NameEvidence: EvDNSAnswer}
		tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer)
		opt := PacketScanOptions{}
		if scoped {
			opt.IssuerIdentity = func(_ string, at time.Time) string {
				if at.Before(base.Add(time.Second)) {
					return "A"
				}
				return "B"
			}
		}
		_, _, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(context.Background(), []string{path}, []*DNSTransaction{tx}, false, false, nil, false, nil, nil, 0, opt)
		if err != nil {
			t.Fatal(err)
		}
		if scoped {
			if tx.DestinationPort != nil || len(tx.ObservedEndpointBindings) != 0 {
				t.Fatal("previous owner's transaction acquired connection evidence")
			}
		} else if tx.DestinationPort == nil || len(tx.ObservedEndpointBindings) != 1 {
			t.Fatal("legacy correlation changed")
		}
	}
}
