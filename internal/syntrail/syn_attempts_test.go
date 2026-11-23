package syntrail

import (
	"context"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestSYNIndexLayoutAndRelease(t *testing.T) {
	if size := unsafe.Sizeof(synAttemptKey{}); size != 16 {
		t.Fatalf("SYN index key occupies %d bytes", size)
	}
	if runtime.GOARCH == "amd64" && (unsafe.Sizeof(Record{}) != 48 || unsafe.Sizeof(compactTCPRecord{}) != 40) {
		t.Fatalf("unexpected record and slot sizes: %d, %d", unsafe.Sizeof(Record{}), unsafe.Sizeof(compactTCPRecord{}))
	}
	ip := netip.MustParseAddr("10.1.0.1")
	batch := []Record{{SrcIP: ip.As4(), DstIP: ip.As4(), DstPort: 443, Protocol: ProtocolTCP, hasSYNHeader: true}}
	acc := NewAccumulator()
	acc.Add(batch)
	acc.Add(batch)
	if len(acc.seenSYNs[""]) != 1 || !batch[0].hasSYNHeader {
		t.Fatal("the accumulator must own its key without consuming the input header")
	}
	if out := acc.TakeRecords(); len(out) != 1 || out[0].hasSYNHeader || acc.seenSYNs != nil {
		t.Fatalf("unexpected retained records or index after transfer: %+v", out)
	}
}

func TestSYNRetryIdentityAcrossFilesAndSubscribers(t *testing.T) {
	const src, dst = "10.1.0.1", "192.0.2.1"
	base := time.Date(2026, 11, 18, 0, 0, 0, 123, time.UTC)
	syn := func(offset time.Duration, client, server string, sport, dport uint16, seq uint32) testPacket {
		return tcp4PacketWithHeader(base.Add(offset), client, server, sport, dport, seq, true, false)
	}
	record := func(offset time.Duration, client, server string, port uint16, identity string) Record {
		return Record{FleetIdentity: identity, SrcIP: netip.MustParseAddr(client).As4(), DstIP: netip.MustParseAddr(server).As4(),
			DstPort: port, Protocol: ProtocolTCP, Timestamp: base.Add(offset).UnixNano()}
	}
	opt := ScanOptions{FleetIdentity: func(r Record) string {
		switch r.CaptureTime().Sub(base) {
		case 7 * time.Hour:
			return "second subscriber"
		case 8 * time.Hour, 9 * time.Hour:
			return ""
		default:
			return "first subscriber"
		}
	}}
	first := writePCAP(t, []testPacket{
		syn(0, src, dst, 0, 443, 0),
		syn(time.Second, src, dst, 0, 443, 0),
		syn(2*time.Second, src, dst, 0, 443, ^uint32(0)),
		syn(3*time.Second, src, dst, 1, 443, 0),
		syn(4*time.Second, src, dst, 0, 8443, 0),
		syn(5*time.Second, "10.1.0.2", dst, 0, 443, 0),
		syn(6*time.Second, src, "192.0.2.2", 0, 443, 0),
	})
	second := writePCAPNG(t, []testPacket{
		syn(-time.Hour, src, dst, 0, 443, 0), // Earlier clock time in a later file.
		syn(6*time.Hour, src, dst, 0, 443, 0),
		syn(7*time.Hour, src, dst, 0, 443, 0),
		syn(8*time.Hour, src, dst, 0, 443, 0),
		syn(9*time.Hour, src, dst, 0, 443, 0),
		tcp4PacketWithHeader(base.Add(10*time.Hour), src, dst, 0, 443, 99, true, true),
	})
	want := []Record{
		record(0, src, dst, 443, "first subscriber"),
		record(2*time.Second, src, dst, 443, "first subscriber"),
		record(3*time.Second, src, dst, 443, "first subscriber"),
		record(4*time.Second, src, dst, 8443, "first subscriber"),
		record(5*time.Second, "10.1.0.2", dst, 443, "first subscriber"),
		record(6*time.Second, src, "192.0.2.2", 443, "first subscriber"),
		record(7*time.Hour, src, dst, 443, "second subscriber"),
		record(8*time.Hour, src, dst, 443, ""),
	}
	one, err := ScanFileWithOptions(context.Background(), first, opt)
	if err != nil || !reflect.DeepEqual(one, want[:6]) {
		t.Fatalf("single file = %+v, %v; want %+v", one, err, want[:6])
	}
	for _, workers := range []int{1, 2} {
		opt.Workers = workers
		got, err := ScanFilesWithOptions(context.Background(), []string{first, second, first}, opt)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("workers %d: got %+v, %v; want %+v", workers, got, err, want)
		}
	}
}
