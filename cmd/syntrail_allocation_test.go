package cmd

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestOwnedSummaryFiltersPreserveLateControlAndOrder(t *testing.T) {
	src, dst, other := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	makeRecord := func(ip netip.Addr, port uint16, proto syntrail.Protocol) syntrail.Record {
		return syntrail.Record{SrcIP: src, DstIP: ip, DstPort: port, Protocol: proto}
	}
	original := []syntrail.Record{
		makeRecord(dst, 12000, syntrail.ProtocolTCP),
		makeRecord(dst, 33434, syntrail.ProtocolUDP),
		makeRecord(dst, 6514, syntrail.ProtocolUDP),
		makeRecord(dst, 80, syntrail.ProtocolTCP),
		makeRecord(other, 12000, syntrail.ProtocolTCP),
		makeRecord(dst, 21, ""),
	}
	opt := synTrailArtifactOptions{FTPControlPorts: map[uint16]struct{}{21: {}}, FTPPassiveMinPort: 10000, ServerSummaryExcludeUDPPorts: map[uint16]struct{}{33434: {}}}
	owned := append([]syntrail.Record(nil), original...)
	backing := owned[:cap(owned)]
	got := filterOwnedPassiveFTPServerSummaryRecords(owned, opt)
	got = filterOwnedUDPServerSummaryRecords(got, opt.ServerSummaryExcludeUDPPorts)
	want := []syntrail.Record{original[2], original[3], original[4], original[5]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if &got[0] != &backing[0] {
		t.Fatal("filter allocated another record buffer")
	}
	for _, record := range backing[len(got):] {
		if record != (syntrail.Record{}) {
			t.Fatal("discarded tail retains records")
		}
	}
	// A later artifact sees the original borrowed bucket, not compacted storage.
	if original[0].DstPort != 12000 || original[1].DstPort != 33434 {
		t.Fatal("borrowed evidence changed")
	}
}

func TestTCPSelectionCapacityMatchesQualifyingEvidence(t *testing.T) {
	records := make([]syntrail.Record, 10000)
	for i := range records {
		records[i].Protocol = syntrail.ProtocolUDP
	}
	records[19].Protocol = syntrail.ProtocolTCP
	records[200].Protocol = ""
	got := tcpSYNTrailRecords(records)
	if len(got) != 2 || cap(got) != 2 {
		t.Fatalf("len=%d cap=%d", len(got), cap(got))
	}
	if got[0] != records[19] || got[1] != records[200] {
		t.Fatal("TCP ordering/empty protocol changed")
	}
	got[0].DstPort = 99
	if records[19].DstPort != 0 {
		t.Fatal("TCP selection borrowed mutable input")
	}
}

func BenchmarkSummaryFiltersAllocation(b *testing.B) {
	records := make([]syntrail.Record, 100000)
	for i := range records {
		records[i] = syntrail.Record{Protocol: syntrail.ProtocolTCP, DstPort: 443}
	}
	opt := fleetMemoryArtifactOptions(false)
	for _, owned := range []bool{false, true} {
		b.Run(fmt.Sprintf("owned_%t", owned), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Both variants include the initial independently owned partition.
				selected := make([]syntrail.Record, len(records))
				copy(selected, records)
				if owned {
					selected = filterOwnedPassiveFTPServerSummaryRecords(selected, opt)
					selected = filterOwnedUDPServerSummaryRecords(selected, opt.ServerSummaryExcludeUDPPorts)
				} else {
					selected = filterPassiveFTPServerSummaryRecords(selected, opt)
					selected = filterUDPServerSummaryRecords(selected, opt.ServerSummaryExcludeUDPPorts)
				}
				if len(selected) != len(records) {
					b.Fatal("wrong count")
				}
			}
		})
	}
}
