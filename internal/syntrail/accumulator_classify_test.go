package syntrail

import (
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
)

func TestTakeClassifiedRecordsMatchesTransfer(t *testing.T) {
	fleet, err := ParseFleetSubnets([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	addrs := [][4]byte{{10, 0, 0, 1}, {10, 0, 0, 2}, {192, 168, 1, 1}, {8, 8, 8, 8}, {169, 254, 0, 1}}
	for _, withCache := range []bool{false, true} {
		for _, n := range []int{0, 1, accumulatorChunkRecords + 1, 3*accumulatorChunkRecords + 99} {
			old, new := NewAccumulator(), NewAccumulator()
			rng := rand.New(rand.NewSource(42))
			for i := 0; i < n; i++ {
				rec := Record{SrcIP: addrs[rng.Intn(len(addrs))], DstIP: addrs[rng.Intn(len(addrs))], DstPort: uint16(rng.Intn(6)), Protocol: []Protocol{ProtocolTCP, ProtocolUDP, 0}[rng.Intn(3)], Timestamp: int64(rng.Intn(9) - 4), MissingTime: i%19 == 0, SyslogQualified: i%2 == 0, FleetIdentity: []string{"", "a", "b"}[i%3]}
				if i%5 == 0 && rec.Protocol == ProtocolTCP {
					rec.hasSYNHeader = true
					rec.synSeq = uint32(i % 11)
					rec.synSrcPort = uint16(i % 7)
				}
				// Deliberate retries, UDP timestamp ties, and later earlier observations.
				batch := []Record{rec, rec}
				earlier := rec
				earlier.Timestamp--
				batch = append(batch, earlier)
				old.Add(batch)
				new.Add(batch)
				clear(batch)
			}
			var cache *SyslogCache
			if withCache {
				cache = NewSyslogCache()
				for _, addr := range addrs {
					cache.Add(netip.AddrFrom4(addr), 3)
				}
			}
			records := old.TakeRecords()
			if new.RecordCount() != len(records) {
				t.Fatal("count differs")
			}
			ApplySyslogQualifications(records, cache)
			want := ClassifyRecords(records, fleet)
			got := new.TakeClassifiedRecords(fleet, cache)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cache=%v n=%d: buckets/order/flags differ", withCache, n)
			}
			for _, bucket := range got {
				if cap(bucket) != len(bucket) {
					t.Fatal("inexact capacity")
				}
			}
			if new.seenSYNs != nil || new.tcpChunks != nil || new.tail.slots != nil || new.tail.exceptions != nil || new.udpRecords != nil || new.udpOrder != nil {
				t.Fatal("accumulator retained consumed storage")
			}
			// Changing returned storage must not affect another bucket.
			for key, bucket := range got {
				if len(bucket) > 0 {
					previous := bucket[0].DstPort
					bucket[0].DstPort = 65000
					for other, rows := range got {
						if key != other && len(rows) > 0 && rows[0].DstPort == 65000 {
							t.Fatal("aliased buckets")
						}
					}
					bucket[0].DstPort = previous
				}
			}
		}
	}
}

func BenchmarkAccumulatorClassification(b *testing.B) {
	fleet, _ := ParseFleetSubnets([]string{"10.0.0.0/24"})
	records := make([]Record, 100000)
	for i := range records {
		records[i] = Record{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{8, 8, 8, 8}, DstPort: 443, Protocol: ProtocolTCP, Timestamp: int64(i)}
	}
	for _, fused := range []bool{false, true} {
		name := "transfer_then_classify"
		if fused {
			name = "direct"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				a := NewAccumulator()
				a.Add(records)
				var buckets BucketedRecords
				if fused {
					buckets = a.TakeClassifiedRecords(fleet, nil)
				} else {
					buckets = ClassifyRecords(a.TakeRecords(), fleet)
				}
				if len(buckets[BucketFleetToNonFleet]) != len(records) {
					b.Fatal("count differs")
				}
			}
		})
	}
}
