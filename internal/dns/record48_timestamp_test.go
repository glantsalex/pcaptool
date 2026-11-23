package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestRecord48PCAPNGTimestampPresenceByReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-and-epoch.pcapng")
	writeRecord48PCAPNG(t, path, []record48Packet{
		{simple: true, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		{nanos: 0, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 8443, true, false)},
	})
	strict, err := syntrail.ScanFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(strict) != 2 || !strict[0].MissingTime || strict[1].MissingTime || strict[0].Timestamp != 0 || strict[1].Timestamp != 0 {
		t.Fatalf("strict SPB/epoch presence = %+v", strict)
	}
	var strictCSV bytes.Buffer
	if err := syntrail.WriteTrailCSV(&strictCSV, strict); err != nil {
		t.Fatal(err)
	}
	const wantStrict = "src_ip,dst_ip,dst_port,syn_timestamp_utc\n10.0.0.1,203.0.113.10,443,0001-01-01 00:00:00.000\n10.0.0.1,203.0.113.10,8443,1970-01-01 00:00:00.000\n"
	if strictCSV.String() != wantStrict {
		t.Fatalf("strict missing/epoch trail = %q, want %q", strictCSV.String(), wantStrict)
	}

	var rawTimes []time.Time
	var shared []syntrail.Record
	_, _, err = AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{NewFileObserver: func(_ int, _ string) PacketFileObserver {
			collector := syntrail.NewCollector()
			return PacketFileObserver{
				Observe: func(packet gopacket.Packet) error {
					rawTimes = append(rawTimes, packet.Metadata().Timestamp)
					return collector.Observe(packet)
				},
				Commit: func() { shared = collector.TakeRecords() },
			}
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	// libpcap exposes no timestamp-presence bit. On the pinned libpcap reader,
	// both an SPB and an epoch EPB arrive as Unix zero, so neither can be marked
	// missing without also corrupting genuine epoch observations.
	if len(rawTimes) != 2 || !rawTimes[0].Equal(time.Unix(0, 0)) || !rawTimes[1].Equal(time.Unix(0, 0)) {
		t.Fatalf("libpcap SPB/epoch timestamps = %v, want two epoch values", rawTimes)
	}
	if len(shared) != 2 || shared[0].MissingTime || shared[1].MissingTime || shared[0].Timestamp != 0 || shared[1].Timestamp != 0 {
		t.Fatalf("shared SPB/epoch presence = %+v", shared)
	}
	var sharedCSV bytes.Buffer
	if err := syntrail.WriteTrailCSV(&sharedCSV, shared); err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(wantStrict, "0001-01-01 00:00:00.000", "1970-01-01 00:00:00.000", 1); sharedCSV.String() != want {
		t.Fatalf("shared missing/epoch trail = %q, want %q", sharedCSV.String(), want)
	}
}

func TestRecord48TimestampErrorRejectsFileBeforeCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out-of-range.pcapng")
	writeRecord48PCAPNG(t, path, []record48Packet{
		{nanos: 1, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		{nanos: 2, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.11", 40000, 8443, true, false)},
		{nanos: uint64(math.MaxInt64) + 1, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.12", 40000, 9443, true, false)},
	})
	admit := func(packet gopacket.Packet) bool {
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		return tcp != nil && tcp.DstPort != 443
	}
	checkError := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "packet 3") || !strings.Contains(err.Error(), "outside signed Unix nanosecond range") {
			t.Fatalf("error = %v, want capture, absolute packet ordinal and timestamp range", err)
		}
	}
	t.Run("shared", func(t *testing.T) {
		committed, readErrors := false, 0
		edges, _, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
			context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
			PacketScanOptions{PacketAdmission: admit, NewFileObserver: func(_ int, _ string) PacketFileObserver {
				collector := syntrail.NewCollector()
				return PacketFileObserver{
					Observe:     collector.Observe,
					OnReadError: func(context.Context, error) error { readErrors++; return nil },
					Commit:      func() { committed = true },
				}
			}},
		)
		checkError(t, err)
		if committed || len(edges) != 0 || readErrors != 0 {
			t.Fatalf("invalid file committed=%v edges=%d read retries=%d", committed, len(edges), readErrors)
		}
	})
	t.Run("strict batch", func(t *testing.T) {
		records, err := syntrail.ScanPacketBatch(context.Background(), path, syntrail.ScanOptions{PacketAdmission: admit})
		checkError(t, err)
		if records != nil {
			t.Fatalf("invalid file returned partial records: %+v", records)
		}
	})
	t.Run("standalone", func(t *testing.T) {
		records, err := syntrail.ScanFilesWithOptions(context.Background(), []string{path}, syntrail.ScanOptions{Workers: 2, PacketAdmission: admit})
		checkError(t, err)
		if records != nil {
			t.Fatalf("invalid scan returned partial records: %+v", records)
		}
	})
}

type record48Packet struct {
	simple bool
	nanos  uint64
	data   []byte
}

func TestRecord48UDPTimestampErrorRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp-invalid-time.pcapng")
	writeRecord48PCAPNG(t, path, []record48Packet{
		{nanos: 1, data: buildSharedObserverUDP(t, "10.0.0.1", "203.0.113.10", 40000, 514)},
		{nanos: uint64(math.MaxInt64) + 1, data: buildSharedObserverUDP(t, "10.0.0.1", "203.0.113.11", 40000, 514)},
	})
	records, err := syntrail.ScanPacketBatch(context.Background(), path, syntrail.ScanOptions{})
	if err == nil || records != nil || !strings.Contains(err.Error(), "packet 2") {
		t.Fatalf("strict UDP records=%v error=%v", records, err)
	}
	committed := false
	edges, _, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{NewFileObserver: func(_ int, _ string) PacketFileObserver {
			collector := syntrail.NewCollector()
			return PacketFileObserver{Observe: collector.Observe, Commit: func() { committed = true }}
		}},
	)
	if err == nil || committed || len(edges) != 0 || !strings.Contains(err.Error(), "packet 2") || !strings.Contains(err.Error(), path) {
		t.Fatalf("shared UDP committed=%t edges=%v error=%v", committed, edges, err)
	}
}

// Write blocks directly so SPBs really omit their timestamps and an EPB can
// encode MaxInt64+1 ns without calling time.Time.UnixNano outside its domain.
func writeRecord48PCAPNG(t *testing.T, path string, packets []record48Packet) {
	t.Helper()
	var capture bytes.Buffer
	block := func(kind uint32, body []byte) {
		length := uint32(12 + len(body))
		for _, part := range []any{kind, length, body, length} {
			if err := binary.Write(&capture, binary.LittleEndian, part); err != nil {
				t.Fatal(err)
			}
		}
	}
	var section bytes.Buffer
	for _, part := range []any{uint32(0x1a2b3c4d), uint16(1), uint16(0), uint64(math.MaxUint64)} {
		if err := binary.Write(&section, binary.LittleEndian, part); err != nil {
			t.Fatal(err)
		}
	}
	block(0x0a0d0d0a, section.Bytes())
	var iface bytes.Buffer
	for _, part := range []any{uint16(layers.LinkTypeEthernet), uint16(0), uint32(65535), uint16(9), uint16(1), []byte{9, 0, 0, 0}, uint32(0)} {
		if err := binary.Write(&iface, binary.LittleEndian, part); err != nil {
			t.Fatal(err)
		}
	}
	block(1, iface.Bytes())
	for _, packet := range packets {
		var body bytes.Buffer
		if !packet.simple {
			for _, part := range []uint32{0, uint32(packet.nanos >> 32), uint32(packet.nanos), uint32(len(packet.data))} {
				if err := binary.Write(&body, binary.LittleEndian, part); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := binary.Write(&body, binary.LittleEndian, uint32(len(packet.data))); err != nil {
			t.Fatal(err)
		}
		body.Write(packet.data)
		body.Write(make([]byte, (4-len(packet.data)%4)%4))
		kind := uint32(6)
		if packet.simple {
			kind = 3
		}
		block(kind, body.Bytes())
	}
	if err := os.WriteFile(path, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}
