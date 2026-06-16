package syntrail

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

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
