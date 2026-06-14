package syntrail

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	fleet := testFleetSet("10.0.0.1", "10.0.0.2")

	tests := []struct {
		name string
		r    Record
		want Bucket
		ok   bool
	}{
		{
			name: "fleet source to non-fleet destination",
			r:    testRecord("10.0.0.1", "10.0.0.99", 443),
			want: BucketFleetToNonFleet,
			ok:   true,
		},
		{
			name: "fleet source to fleet destination",
			r:    testRecord("10.0.0.1", "10.0.0.2", 443),
			want: BucketFleetToFleet,
			ok:   true,
		},
		{
			name: "private non-fleet source to fleet destination",
			r:    testRecord("192.168.1.10", "10.0.0.2", 443),
			want: BucketPrivateNonFleetToFleet,
			ok:   true,
		},
		{
			name: "discard private non-fleet to non-fleet",
			r:    testRecord("192.168.1.10", "10.0.0.99", 443),
			ok:   false,
		},
		{
			name: "discard public source",
			r:    testRecord("8.8.8.8", "10.0.0.2", 443),
			ok:   false,
		},
		{
			name: "discard public fleet source",
			r:    testRecord("203.0.113.10", "10.0.0.99", 443),
			ok:   false,
		},
		{
			name: "discard zero destination port",
			r:    testRecord("10.0.0.1", "10.0.0.2", 0),
			ok:   false,
		},
		{
			name: "discard IPv6 source",
			r:    testRecord("2001:db8::1", "10.0.0.2", 443),
			ok:   false,
		},
		{
			name: "discard IPv6 destination",
			r:    testRecord("10.0.0.1", "2001:db8::1", 443),
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Classify(tt.r, fleet)
			if ok != tt.ok {
				t.Fatalf("Classify() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("Classify() bucket = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyRecordsGroupsRecords(t *testing.T) {
	fleet := testFleetSet("10.0.0.1", "10.0.0.2", "203.0.113.10")
	fleetToNonFleet := testRecord("10.0.0.1", "10.0.0.99", 443)
	fleetToFleet := testRecord("10.0.0.1", "10.0.0.2", 443)
	privateNonFleetToFleet := testRecord("192.168.1.10", "10.0.0.2", 443)
	discarded := testRecord("8.8.8.8", "10.0.0.2", 443)

	got := ClassifyRecords([]Record{
		fleetToNonFleet,
		fleetToFleet,
		privateNonFleetToFleet,
		discarded,
	}, fleet)

	want := BucketedRecords{
		BucketFleetToNonFleet:        {fleetToNonFleet},
		BucketFleetToFleet:           {fleetToFleet},
		BucketPrivateNonFleetToFleet: {privateNonFleetToFleet},
	}

	if len(got) != len(want) {
		t.Fatalf("len(ClassifyRecords()) = %d, want %d", len(got), len(want))
	}
	for bucket, wantRecords := range want {
		gotRecords := got[bucket]
		if len(gotRecords) != len(wantRecords) {
			t.Fatalf("len(ClassifyRecords()[%q]) = %d, want %d", bucket, len(gotRecords), len(wantRecords))
		}
		for i := range wantRecords {
			if gotRecords[i] != wantRecords[i] {
				t.Fatalf("ClassifyRecords()[%q][%d] = %+v, want %+v", bucket, i, gotRecords[i], wantRecords[i])
			}
		}
	}
}

func testFleetSet(ips ...string) FleetSet {
	fleet := FleetSet{ips: make(map[netip.Addr]struct{}, len(ips))}
	for _, ip := range ips {
		fleet.ips[netip.MustParseAddr(ip)] = struct{}{}
	}
	return fleet
}

func testRecord(src, dst string, dstPort uint16) Record {
	return Record{
		SrcIP:   netip.MustParseAddr(src),
		DstIP:   netip.MustParseAddr(dst),
		DstPort: dstPort,
	}
}
