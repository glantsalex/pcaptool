package syntrail

import (
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestAccumulatorChunkBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, accumulatorChunkRecords - 1, accumulatorChunkRecords, accumulatorChunkRecords + 1, 2*accumulatorChunkRecords - 1, 2 * accumulatorChunkRecords, 2*accumulatorChunkRecords + 1} {
		for _, withUDP := range []bool{false, true} {
			t.Run(fmt.Sprintf("records=%d/udp=%t", count, withUDP), func(t *testing.T) {
				acc := NewAccumulator()
				var reference referenceAccumulator
				r := Record{FleetIdentity: "device-a", SrcIP: netip.MustParseAddr("10.0.0.1").As4(), DstIP: netip.MustParseAddr("203.0.113.1").As4(), DstPort: 443, Protocol: ProtocolTCP, Timestamp: time.Unix(1, 0).UTC().UnixNano()}
				if withUDP {
					udp := r
					udp.Protocol = ProtocolUDP
					acc.Add([]Record{udp})
					reference.add([]Record{udp})
				}
				var first *compactTCPRecord
				for i := 0; i < count; i++ {
					r.Timestamp++
					acc.Add([]Record{r})
					reference.add([]Record{r})
					if i == accumulatorChunkRecords-1 {
						first = &acc.tail.slots[0]
					}
				}
				if count > accumulatorChunkRecords && &acc.tcpChunks[0].slots[0] != first {
					t.Fatal("completed chunk moved during later appends")
				}
				wantChunks := 0
				if count > 0 {
					wantChunks = (count - 1) / accumulatorChunkRecords
				}
				if len(acc.tcpChunks) != wantChunks || cap(acc.tail.slots) > accumulatorChunkRecords {
					t.Fatalf("unexpected chunk layout: complete=%d tail=%d/%d", len(acc.tcpChunks), len(acc.tail.slots), cap(acc.tail.slots))
				}
				for _, chunk := range acc.tcpChunks {
					if len(chunk.slots) != accumulatorChunkRecords || cap(chunk.slots) != accumulatorChunkRecords {
						t.Fatal("completed chunk is not full and bounded")
					}
				}
				// Keep the descriptors to verify finalization clears their pointers.
				descriptors := acc.tcpChunks
				got := acc.TakeRecords()
				if want := reference.records(); !reflect.DeepEqual(got, want) {
					t.Fatalf("records differ: got %d, want %d", len(got), len(want))
				}
				if wantChunks > 0 && cap(got) != len(got) {
					t.Fatalf("flattened capacity = %d, want %d", cap(got), len(got))
				}
				assertAccumulatorReleased(t, acc)
				for _, chunk := range descriptors {
					if chunk.slots != nil || chunk.exceptions != nil {
						t.Fatal("completed chunk reference retained after flattening")
					}
				}
			})
		}
	}
}

func TestAccumulatorChunkAllocationIsLazy(t *testing.T) {
	acc := NewAccumulator()
	if acc.tail.slots != nil || acc.tail.exceptions != nil || acc.tcpChunks != nil {
		t.Fatal("empty accumulator allocated TCP storage")
	}
	acc.Add([]Record{{Protocol: ProtocolUDP}})
	if acc.tail.slots != nil || acc.tail.exceptions != nil || acc.tcpChunks != nil {
		t.Fatal("UDP-only accumulator allocated TCP storage")
	}
	acc.Add([]Record{{Protocol: ProtocolTCP}})
	if cap(acc.tail.slots) != 1 {
		t.Fatalf("one record allocated capacity %d, want 1", cap(acc.tail.slots))
	}
}

func assertAccumulatorReleased(t *testing.T, acc *Accumulator) {
	t.Helper()
	if acc.tail.slots != nil || acc.tail.exceptions != nil || acc.tcpChunks != nil || acc.udpRecords != nil || acc.udpOrder != nil {
		t.Fatal("accumulator retained transferred storage")
	}
}

func TestAccumulatorTCPEncoding(t *testing.T) {
	size := unsafe.Sizeof(compactTCPRecord{})
	t.Logf("%s: TCP slot %d bytes, full record %d bytes", runtime.GOARCH, size, unsafe.Sizeof(Record{}))
	if runtime.GOARCH == "amd64" && size != 40 {
		t.Fatalf("TCP slot size = %d, want 40", size)
	}
	for _, tc := range tcpEncodingCases() {
		t.Run(tc.name, func(t *testing.T) {
			acc := NewAccumulator()
			acc.Add([]Record{tc.record})
			if common := acc.tail.slots[0].exception == 0; common != tc.common {
				t.Fatalf("packed = %v, want %v", common, tc.common)
			}
			if tc.common && acc.tail.exceptions != nil || !tc.common && len(acc.tail.exceptions) != 1 {
				t.Fatalf("unexpected exception storage: %d records", len(acc.tail.exceptions))
			}
			if got := acc.TakeRecords(); len(got) != 1 || got[0] != tc.record {
				t.Fatalf("inexact round-trip: %#v", got)
			}
			assertAccumulatorReleased(t, acc)
		})
	}
}

func TestAccumulatorAllExceptionsAcrossChunks(t *testing.T) {
	input := make([]Record, accumulatorChunkRecords+1)
	for i := range input {
		input[i] = Record{DstPort: uint16(i), Protocol: 0}
	}
	acc := NewAccumulator()
	acc.Add(input)
	completed := acc.tcpChunks
	if last := completed[0].slots[accumulatorChunkRecords-1].exception; last != accumulatorChunkRecords || acc.tail.slots[0].exception != 1 {
		t.Fatal("exception indexes did not cover and restart at the chunk boundary")
	}
	if got := acc.TakeRecords(); !reflect.DeepEqual(got, input) {
		t.Fatal("full chunk of exceptions did not round-trip")
	}
	if completed[0].slots != nil || completed[0].exceptions != nil {
		t.Fatal("completed chunk retained slot or exception storage")
	}
	assertAccumulatorReleased(t, acc)
}
