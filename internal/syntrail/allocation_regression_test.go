package syntrail

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestServerSummaryDuplicateHeavyContract(t *testing.T) {
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	pattern := []Record{
		{DstIP: b, DstPort: 443, Protocol: ProtocolTCP},
		{DstIP: a, DstPort: 53, Protocol: ProtocolUDP},
		{DstIP: b, DstPort: 80, Protocol: ""},
		{DstIP: a, DstPort: 80, Protocol: ProtocolTCP},
		{DstIP: b, DstPort: 80, Protocol: ProtocolTCP},
	}
	records := make([]Record, 0, 5000)
	for i := 0; i < 1000; i++ {
		records = append(records, pattern...)
	}
	original := append([]Record(nil), records...)
	want := []ServerTuple{{DstIP: a, DstPort: 80, Protocol: ProtocolTCP}, {DstIP: b, DstPort: 80, Protocol: ProtocolTCP}, {DstIP: b, DstPort: 443, Protocol: ProtocolTCP}, {DstIP: a, DstPort: 53, Protocol: ProtocolUDP}}
	if got := PrivateServerTuples(records); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatal("summary mutated input")
	}
	if got := PrivateServerTuples(nil); got == nil || len(got) != 0 {
		t.Fatal("empty summary contract changed")
	}
}

func TestSelectLocalityOwnedExactStorage(t *testing.T) {
	pub := Record{DstIP: netip.MustParseAddr("203.0.113.1")}
	local := Record{DstIP: netip.MustParseAddr("10.0.0.1")}
	shared := Record{DstIP: netip.MustParseAddr("100.64.0.1")}
	for _, input := range [][]Record{nil, {}, {pub, pub}, {local, shared}, {pub, local, pub, shared}} {
		original := append([]Record(nil), input...)
		for _, private := range []bool{false, true} {
			want := make([]Record, 0)
			for _, record := range input {
				if (record == local || record == shared) == private {
					want = append(want, record)
				}
			}
			got := SelectFleetToNonFleetByDestinationLocality(input, private)
			if !reflect.DeepEqual(got, want) || cap(got) != len(want) {
				t.Fatalf("selection %v cap=%d want %v", got, cap(got), want)
			}
			if len(got) > 0 {
				got[0].DstPort = 9999
			}
		}
		if len(input) != len(original) {
			t.Fatal("input length changed")
		}
		for i := range input {
			if input[i] != original[i] {
				t.Fatal("selection aliases input")
			}
		}
	}
}

func benchmarkSummaryRecords(n, distinct int) []Record {
	records := make([]Record, n)
	for i := range records {
		j := i % distinct
		records[i] = Record{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.AddrFrom4([4]byte{203, byte(j >> 16), byte(j >> 8), byte(j)}), DstPort: 443, Protocol: ProtocolTCP, Timestamp: time.Unix(int64(i), 0)}
	}
	return records
}

func BenchmarkServerSummaryAllocation(b *testing.B) {
	for _, distinct := range []int{16, 100000} {
		records := benchmarkSummaryRecords(100000, distinct)
		for _, legacy := range []bool{true, false} {
			b.Run(fmt.Sprintf("distinct_%d/baseline_%t", distinct, legacy), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var rows []ServerTuple
					if legacy {
						rows = baselinePrivateServerTuples(records)
					} else {
						rows = PrivateServerTuples(records)
					}
					if len(rows) != distinct {
						b.Fatal("wrong unique count")
					}
				}
			})
		}
	}
}

func BenchmarkLocalitySelectionAllocation(b *testing.B) {
	records := benchmarkSummaryRecords(100000, 1000)
	for i := 0; i < len(records); i += 100 {
		records[i].DstIP = netip.MustParseAddr("10.0.0.2")
	}
	for _, legacy := range []bool{true, false} {
		b.Run(fmt.Sprintf("baseline_%t", legacy), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var selected []Record
				if legacy {
					_, selected = SplitFleetToNonFleetByDestinationLocality(records)
				} else {
					selected = SelectFleetToNonFleetByDestinationLocality(records, true)
				}
				if len(selected) != 1000 {
					b.Fatal("wrong selection")
				}
			}
		})
	}
}

// Frozen pre-fix implementation. Keep independent of the optimized builder.
func baselinePrivateServerTuples(records []Record) []ServerTuple {
	seen := make(map[ServerTuple]struct{}, len(records))
	rows := make([]ServerTuple, 0, len(records))
	for _, record := range records {
		row := ServerTuple{
			DstIP:    record.DstIP,
			DstPort:  record.DstPort,
			Protocol: normalizedProtocol(record.Protocol),
		}
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		left := rows[i]
		right := rows[j]

		if leftRank, rightRank := protocolRank(left.Protocol), protocolRank(right.Protocol); leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.DstPort != right.DstPort {
			return left.DstPort < right.DstPort
		}
		if cmp := compareAddr(left.DstIP, right.DstIP); cmp != 0 {
			return cmp < 0
		}
		return left.Protocol < right.Protocol
	})

	return rows
}

// Frozen pre-fix classification allocation pattern. Classification policy itself
// is unchanged; explicit policy/ordering fixtures cover it separately.
func baselineClassifyRecords(records []Record, fleet FleetSet) BucketedRecords {
	out := make(BucketedRecords)
	for _, record := range records {
		if bucket, ok := Classify(record, fleet); ok {
			out[bucket] = append(out[bucket], record)
		}
	}
	return out
}

func BenchmarkClassificationAllocation(b *testing.B) {
	records := benchmarkSummaryRecords(100000, 1000)
	fleet, err := ParseFleetIPv4List(strings.NewReader("10.0.0.1\n"))
	if err != nil {
		b.Fatal(err)
	}
	for _, legacy := range []bool{true, false} {
		b.Run(fmt.Sprintf("baseline_%t", legacy), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var buckets BucketedRecords
				if legacy {
					buckets = baselineClassifyRecords(records, fleet)
				} else {
					buckets = ClassifyRecords(records, fleet)
				}
				if len(buckets[BucketFleetToNonFleet]) != len(records) {
					b.Fatal("wrong count")
				}
			}
		})
	}
}

func TestClassificationExactCapacityAndOwnership(t *testing.T) {
	fleet, err := ParseFleetIPv4List(strings.NewReader("10.0.0.1\n10.0.0.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("10.0.0.1")
	public := Record{SrcIP: src, DstIP: netip.MustParseAddr("203.0.113.1"), DstPort: 443, Protocol: ProtocolTCP}
	peer := Record{SrcIP: src, DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 80}
	probe := Record{SrcIP: netip.MustParseAddr("192.168.0.1"), DstIP: src, DstPort: 22}
	invalid := Record{SrcIP: src, DstIP: public.DstIP, DstPort: 0}
	records := []Record{public, probe, public, invalid, peer}
	original := append([]Record(nil), records...)
	want := BucketedRecords{BucketFleetToNonFleet: {public, public}, BucketFleetToFleet: {peer}, BucketPrivateNonFleetToFleet: {probe}}
	got := ClassifyRecords(records, fleet)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for key, items := range got {
		if cap(items) != len(items) {
			t.Errorf("%s len=%d cap=%d", key, len(items), cap(items))
		}
		items[0].DstPort = 999
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatal("classified buckets alias input")
	}
	for _, input := range [][]Record{nil, {}, {invalid}} {
		if got := ClassifyRecords(input, fleet); got == nil || len(got) != 0 {
			t.Fatal("empty/rejected bucket semantics changed")
		}
	}
}

func TestAccumulatorExactExpansionPreservesRecords(t *testing.T) {
	tcp := Record{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.1"), DstPort: 443, Protocol: ProtocolTCP}
	udp := tcp
	udp.Protocol = ProtocolUDP
	udp.DstPort = 6514
	udp.SyslogQualified = true
	acc := NewAccumulator()
	acc.tcpRecords = make([]Record, 2, 2)
	acc.tcpRecords[0] = tcp
	acc.tcpRecords[1] = tcp
	acc.Add([]Record{udp})
	got := acc.TakeRecords()
	if !reflect.DeepEqual(got, []Record{tcp, tcp, udp}) || cap(got) != 3 {
		t.Fatalf("got %v cap=%d", got, cap(got))
	}
	if acc.tcpRecords != nil || acc.udpRecords != nil || acc.udpOrder != nil {
		t.Fatal("transferred references retained")
	}
}

func BenchmarkAccumulatorFinalizationAllocation(b *testing.B) {
	tcp := benchmarkSummaryRecords(100000, 1)
	udp := tcp[0]
	udp.Protocol = ProtocolUDP
	for _, legacy := range []bool{true, false} {
		b.Run(fmt.Sprintf("baseline_%t", legacy), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				acc := NewAccumulator()
				acc.tcpRecords = make([]Record, len(tcp))
				copy(acc.tcpRecords, tcp)
				acc.Add([]Record{udp})
				var records []Record
				if legacy {
					for _, key := range acc.udpOrder {
						acc.tcpRecords = append(acc.tcpRecords, acc.udpRecords[key])
					}
					records = acc.tcpRecords
				} else {
					records = acc.TakeRecords()
				}
				if len(records) != len(tcp)+1 {
					b.Fatal("wrong count")
				}
			}
		})
	}
}

func TestServerSummaryMatchesBaselineAcrossInputOrders(t *testing.T) {
	addresses := []netip.Addr{{}, netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:203.0.113.1")}
	protocols := []Protocol{"", ProtocolTCP, ProtocolUDP, "other"}
	for _, seed := range []int64{1, 42, 401240} {
		rng := rand.New(rand.NewSource(seed))
		records := make([]Record, 10000)
		for i := range records {
			records[i] = Record{DstIP: addresses[rng.Intn(len(addresses))], DstPort: uint16(rng.Intn(32)), Protocol: protocols[rng.Intn(len(protocols))]}
		}
		if got, want := PrivateServerTuples(records), baselinePrivateServerTuples(records); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: summary changed", seed)
		}
	}
}
