package syntrail

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestSplitFleetToNonFleetPreservesIndependentStorageAndEmptySlices(t *testing.T) {
	ts := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	publicRecord := testSplitRecord("10.0.0.1", "203.0.113.10", 443, ts)
	privateRecord := testSplitRecord("10.0.0.1", "192.168.1.20", 8443, ts)
	for _, records := range [][]Record{nil, {}, {publicRecord}, {privateRecord}, {privateRecord, publicRecord, privateRecord}} {
		t.Run(fmt.Sprintf("records_%d_private_%t", len(records), len(records) > 0 && records[0] == privateRecord), func(t *testing.T) {
			input := append([]Record(nil), records...)
			public, private := SplitFleetToNonFleetByDestinationLocality(input)
			if public == nil || private == nil {
				t.Fatal("empty partitions must retain the legacy non-nil slice behavior")
			}
			var wantPublic, wantPrivate []Record
			for _, r := range records {
				if r == privateRecord {
					wantPrivate = append(wantPrivate, r)
				} else {
					wantPublic = append(wantPublic, r)
				}
			}
			if len(public) != len(wantPublic) || len(private) != len(wantPrivate) {
				t.Fatal("partition counts changed")
			}
			for i := range public {
				if public[i] != wantPublic[i] {
					t.Fatal("public partition order changed")
				}
				public[i].DstPort = 1
			}
			for i := range private {
				if private[i] != wantPrivate[i] {
					t.Fatal("private partition order or independent storage changed")
				}
				private[i].DstPort = 2
			}
			for i := range input {
				if input[i] != records[i] {
					t.Fatal("partition mutation changed input storage")
				}
			}
		})
	}
}

func BenchmarkSplitFleetToNonFleetByDestinationLocality(b *testing.B) {
	ts := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	records := make([]Record, 100_000)
	for i := range records {
		dst := "203.0.113.10"
		if i%10 == 0 {
			dst = "192.168.1.20"
		}
		records[i] = testSplitRecord("10.0.0.1", dst, 443, ts)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		public, private := SplitFleetToNonFleetByDestinationLocality(records)
		if len(public)+len(private) != len(records) {
			b.Fatal("partition count changed")
		}
	}
}

func TestSplitFleetToNonFleetByDestinationLocalitySeparatesPublicAndPrivateDestinations(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	publicRecord := testSplitRecord("10.0.0.1", "203.0.113.10", 443, ts)
	privateRecord := testSplitRecord("10.0.0.1", "192.168.1.20", 8443, ts.Add(time.Second))
	cgnatRecord := testSplitRecord("10.0.0.1", "100.64.0.1", 8080, ts.Add(2*time.Second))
	records := []Record{publicRecord, privateRecord, cgnatRecord}
	original := append([]Record(nil), records...)

	public, privateNonFleet := SplitFleetToNonFleetByDestinationLocality(records)

	if want := []Record{publicRecord}; !reflect.DeepEqual(public, want) {
		t.Fatalf("public records = %#v, want %#v", public, want)
	}
	if want := []Record{privateRecord, cgnatRecord}; !reflect.DeepEqual(privateNonFleet, want) {
		t.Fatalf("private non-fleet records = %#v, want %#v", privateNonFleet, want)
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatalf("SplitFleetToNonFleetByDestinationLocality mutated input records: got %#v, want %#v", records, original)
	}
}

func testSplitRecord(src, dst string, dstPort uint16, timestamp time.Time) Record {
	return Record{
		SrcIP:     netip.MustParseAddr(src),
		DstIP:     netip.MustParseAddr(dst),
		DstPort:   dstPort,
		Timestamp: timestamp,
	}
}
