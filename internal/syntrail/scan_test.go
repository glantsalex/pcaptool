package syntrail

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestScanFilesExtractsIPv4TCPSYNRecords(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 30, 45, 123456789, time.FixedZone("capture", 2*60*60))
	path := writePCAP(t, []testPacket{
		tcp4Packet(ts, "10.1.2.3", "203.0.113.10", 443, true, false),
	})

	records, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ScanFiles() returned %d records, want 1", len(records))
	}

	want := Record{
		SrcIP:     netip.MustParseAddr("10.1.2.3"),
		DstIP:     netip.MustParseAddr("203.0.113.10"),
		DstPort:   443,
		Protocol:  ProtocolTCP,
		Timestamp: ts.UTC(),
	}
	if records[0] != want {
		t.Fatalf("record = %+v, want %+v", records[0], want)
	}
	if records[0].Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", records[0].Timestamp.Location())
	}
}

func TestScanFilesExtractsEligibleIPv4UDPRecord(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 123456789, time.FixedZone("capture", 2*60*60))
	path := writePCAP(t, []testPacket{
		udp4Packet(ts, "10.1.2.3", "203.0.113.10", 53),
	})

	records, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	want := []Record{{
		SrcIP:     netip.MustParseAddr("10.1.2.3"),
		DstIP:     netip.MustParseAddr("203.0.113.10"),
		DstPort:   53,
		Protocol:  ProtocolUDP,
		Timestamp: ts.UTC(),
	}}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("ScanFiles() = %+v, want %+v", records, want)
	}
}

func TestScanFilesAcceptsIPv4LinkLocalUDPDestination(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAP(t, []testPacket{
		udp4Packet(ts, "10.1.2.3", "169.254.1.2", 5353),
	})

	records, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	want := []Record{{
		SrcIP:     netip.MustParseAddr("10.1.2.3"),
		DstIP:     netip.MustParseAddr("169.254.1.2"),
		DstPort:   5353,
		Protocol:  ProtocolUDP,
		Timestamp: ts,
	}}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("ScanFiles() = %+v, want %+v", records, want)
	}
}

func TestScanFilesDedupesUDPAtEarliestTimestampAcrossPacketsAndFiles(t *testing.T) {
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	first := writePCAP(t, []testPacket{
		udp4Packet(base.Add(3*time.Second), "10.1.2.3", "203.0.113.10", 53),
		udp4Packet(base.Add(2*time.Second), "10.1.2.3", "203.0.113.10", 53),
		udp4Packet(base.Add(4*time.Second), "10.1.2.3", "203.0.113.10", 5353),
		udp4Packet(base.Add(5*time.Second), "10.1.2.3", "203.0.113.11", 53),
	})
	second := writePCAP(t, []testPacket{
		udp4Packet(base, "10.1.2.3", "203.0.113.10", 53),
	})

	records, err := ScanFiles(context.Background(), []string{first, second})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	want := []Record{
		{
			SrcIP:     netip.MustParseAddr("10.1.2.3"),
			DstIP:     netip.MustParseAddr("203.0.113.10"),
			DstPort:   53,
			Protocol:  ProtocolUDP,
			Timestamp: base,
		},
		{
			SrcIP:     netip.MustParseAddr("10.1.2.3"),
			DstIP:     netip.MustParseAddr("203.0.113.10"),
			DstPort:   5353,
			Protocol:  ProtocolUDP,
			Timestamp: base.Add(4 * time.Second),
		},
		{
			SrcIP:     netip.MustParseAddr("10.1.2.3"),
			DstIP:     netip.MustParseAddr("203.0.113.11"),
			DstPort:   53,
			Protocol:  ProtocolUDP,
			Timestamp: base.Add(5 * time.Second),
		},
	}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("ScanFiles() = %+v, want %+v", records, want)
	}
}

func TestScanFileDedupesUDPWithinOneFile(t *testing.T) {
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAP(t, []testPacket{
		udp4Packet(base.Add(time.Second), "10.1.2.3", "203.0.113.10", 53),
		udp4Packet(base, "10.1.2.3", "203.0.113.10", 53),
	})

	records, err := scanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scanFile() error = %v", err)
	}
	if len(records) != 1 || !records[0].Timestamp.Equal(base) {
		t.Fatalf("scanFile() = %+v, want one UDP record at %v", records, base)
	}
}

func TestScanFilesExcludesIneligiblePackets(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAP(t, []testPacket{
		tcp4Packet(ts, "10.1.2.3", "203.0.113.10", 443, true, true),
		tcp6Packet(ts.Add(time.Second), "fd00::1", "2001:db8::10", 443, true, false),
		tcp4Packet(ts.Add(2*time.Second), "198.51.100.20", "203.0.113.10", 443, true, false),
		tcp4Packet(ts.Add(3*time.Second), "10.1.2.3", "203.0.113.10", 0, true, false),
		udp4Packet(ts.Add(4*time.Second), "198.51.100.20", "203.0.113.10", 53),
		udp4Packet(ts.Add(5*time.Second), "10.1.2.3", "224.0.0.1", 53),
		udp4Packet(ts.Add(6*time.Second), "10.1.2.3", "255.255.255.255", 53),
		udp4Packet(ts.Add(7*time.Second), "10.1.2.3", "0.0.0.0", 53),
		udp4Packet(ts.Add(8*time.Second), "10.1.2.3", "10.1.2.3", 53),
		udp4Packet(ts.Add(9*time.Second), "10.1.2.3", "203.0.113.10", 0),
		udp6Packet(ts.Add(10*time.Second), "fd00::1", "2001:db8::10", 53),
	})

	records, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("ScanFiles() returned %d records, want 0: %+v", len(records), records)
	}
}

func TestScanFilesPreservesTCPFilePacketOrderAndDuplicates(t *testing.T) {
	firstTS := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	secondTS := firstTS.Add(time.Second)

	first := writePCAP(t, []testPacket{
		tcp4Packet(firstTS, "10.0.0.1", "203.0.113.1", 443, true, false),
	})
	second := writePCAP(t, []testPacket{
		tcp4Packet(secondTS, "10.0.0.2", "203.0.113.2", 8443, true, false),
		tcp4Packet(secondTS.Add(time.Second), "10.0.0.2", "203.0.113.2", 8443, true, false),
	})

	records, err := ScanFiles(context.Background(), []string{second, first})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("ScanFiles() returned %d records, want 3", len(records))
	}

	if records[0].SrcIP != netip.MustParseAddr("10.0.0.2") ||
		records[1].SrcIP != netip.MustParseAddr("10.0.0.2") ||
		records[2].SrcIP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("TCP records are out of file/packet order: %+v", records)
	}
}

func TestScanFilesWithOptionsConcurrentMatchesSequentialOrder(t *testing.T) {
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	first := writePCAP(t, []testPacket{
		tcp4Packet(base.Add(10*time.Millisecond), "10.0.0.1", "203.0.113.1", 443, true, false),
		tcp4Packet(base.Add(20*time.Millisecond), "10.0.0.1", "203.0.113.1", 443, true, false),
		udp4Packet(base.Add(10*time.Second), "10.0.0.1", "203.0.113.10", 53),
		udp4Packet(base.Add(12*time.Second), "10.0.0.1", "203.0.113.10", 53),
		udp4Packet(base.Add(2*time.Second), "10.0.0.1", "203.0.113.10", 5353),
	})
	second := writePCAP(t, []testPacket{
		tcp4Packet(base.Add(30*time.Millisecond), "10.0.0.2", "203.0.113.2", 8443, true, false),
		udp4Packet(base, "10.0.0.1", "203.0.113.10", 53),
		udp4Packet(base.Add(3*time.Second), "10.0.0.1", "203.0.113.11", 53),
	})
	third := writePCAP(t, []testPacket{
		tcp4Packet(base.Add(40*time.Millisecond), "10.0.0.3", "203.0.113.3", 9443, true, false),
		tcp4Packet(base.Add(50*time.Millisecond), "10.0.0.3", "203.0.113.3", 9443, true, false),
		udp4Packet(base.Add(4*time.Second), "10.0.0.4", "203.0.113.12", 123),
	})
	files := []string{first, second, third}

	sequential, err := ScanFiles(context.Background(), files)
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	concurrent, err := ScanFilesWithOptions(context.Background(), files, ScanOptions{Workers: 2})
	if err != nil {
		t.Fatalf("ScanFilesWithOptions() error = %v", err)
	}
	if !reflect.DeepEqual(concurrent, sequential) {
		t.Fatalf("concurrent records = %+v, want sequential %+v", concurrent, sequential)
	}

	want := []Record{
		{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("203.0.113.1"),
			DstPort:   443,
			Protocol:  ProtocolTCP,
			Timestamp: base.Add(10 * time.Millisecond),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("203.0.113.1"),
			DstPort:   443,
			Protocol:  ProtocolTCP,
			Timestamp: base.Add(20 * time.Millisecond),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.2"),
			DstIP:     netip.MustParseAddr("203.0.113.2"),
			DstPort:   8443,
			Protocol:  ProtocolTCP,
			Timestamp: base.Add(30 * time.Millisecond),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.3"),
			DstIP:     netip.MustParseAddr("203.0.113.3"),
			DstPort:   9443,
			Protocol:  ProtocolTCP,
			Timestamp: base.Add(40 * time.Millisecond),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.3"),
			DstIP:     netip.MustParseAddr("203.0.113.3"),
			DstPort:   9443,
			Protocol:  ProtocolTCP,
			Timestamp: base.Add(50 * time.Millisecond),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("203.0.113.10"),
			DstPort:   53,
			Protocol:  ProtocolUDP,
			Timestamp: base,
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("203.0.113.10"),
			DstPort:   5353,
			Protocol:  ProtocolUDP,
			Timestamp: base.Add(2 * time.Second),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			DstIP:     netip.MustParseAddr("203.0.113.11"),
			DstPort:   53,
			Protocol:  ProtocolUDP,
			Timestamp: base.Add(3 * time.Second),
		},
		{
			SrcIP:     netip.MustParseAddr("10.0.0.4"),
			DstIP:     netip.MustParseAddr("203.0.113.12"),
			DstPort:   123,
			Protocol:  ProtocolUDP,
			Timestamp: base.Add(4 * time.Second),
		},
	}
	if !reflect.DeepEqual(concurrent, want) {
		t.Fatalf("ScanFilesWithOptions() = %+v, want %+v", concurrent, want)
	}
}

func TestScanFilesWithOptionsWorkersLessThanOrEqualOneMatchSequential(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAP(t, []testPacket{
		tcp4Packet(ts, "10.1.2.3", "203.0.113.10", 443, true, false),
		udp4Packet(ts.Add(time.Second), "10.1.2.3", "203.0.113.11", 53),
	})

	sequential, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	for _, workers := range []int{-1, 0, 1} {
		got, err := ScanFilesWithOptions(context.Background(), []string{path}, ScanOptions{Workers: workers})
		if err != nil {
			t.Fatalf("ScanFilesWithOptions(Workers=%d) error = %v", workers, err)
		}
		if !reflect.DeepEqual(got, sequential) {
			t.Fatalf("ScanFilesWithOptions(Workers=%d) = %+v, want %+v", workers, got, sequential)
		}
	}
}

func TestScanFilesWithOptionsWorkersGreaterThanFiles(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	first := writePCAP(t, []testPacket{
		tcp4Packet(ts, "10.1.2.3", "203.0.113.10", 443, true, false),
	})
	second := writePCAP(t, []testPacket{
		udp4Packet(ts.Add(time.Second), "10.1.2.4", "203.0.113.11", 53),
	})
	files := []string{first, second}

	sequential, err := ScanFiles(context.Background(), files)
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	got, err := ScanFilesWithOptions(context.Background(), files, ScanOptions{Workers: 8})
	if err != nil {
		t.Fatalf("ScanFilesWithOptions() error = %v", err)
	}
	if !reflect.DeepEqual(got, sequential) {
		t.Fatalf("ScanFilesWithOptions() = %+v, want %+v", got, sequential)
	}
}

func TestScanFilesWithOptionsEmptyFileList(t *testing.T) {
	records, err := ScanFilesWithOptions(context.Background(), nil, ScanOptions{Workers: 4})
	if err != nil {
		t.Fatalf("ScanFilesWithOptions() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("ScanFilesWithOptions() returned %d records, want 0", len(records))
	}
}

func TestScanFileReadsPCAPNG(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAPNG(t, []testPacket{
		tcp4Packet(ts, "100.64.1.10", "203.0.113.99", 443, true, false),
	})

	records, err := scanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scanFile() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("scanFile() returned %d records, want 1", len(records))
	}
	if records[0].SrcIP != netip.MustParseAddr("100.64.1.10") {
		t.Fatalf("src IP = %v, want 100.64.1.10", records[0].SrcIP)
	}
}

func TestScanFilesRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	records, err := ScanFiles(ctx, []string{filepath.Join(t.TempDir(), "missing.pcap")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanFiles() error = %v, want context.Canceled", err)
	}
	if records != nil {
		t.Fatalf("ScanFiles() records = %+v, want nil", records)
	}
}

func TestScanFilesWithOptionsRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	records, err := ScanFilesWithOptions(ctx, []string{filepath.Join(t.TempDir(), "missing.pcap")}, ScanOptions{Workers: 2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanFilesWithOptions() error = %v, want context.Canceled", err)
	}
	if records != nil {
		t.Fatalf("ScanFilesWithOptions() records = %+v, want nil", records)
	}
}

func TestScanFilesWithOptionsErrorIncludesFilePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pcap")

	records, err := ScanFilesWithOptions(context.Background(), []string{missing}, ScanOptions{Workers: 2})
	if err == nil {
		t.Fatal("ScanFilesWithOptions() error = nil, want error")
	}
	if records != nil {
		t.Fatalf("ScanFilesWithOptions() records = %+v, want nil", records)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("ScanFilesWithOptions() error = %q, want path %q", err, missing)
	}
}

type testPacket struct {
	ts   time.Time
	data []byte
}

func tcp4Packet(ts time.Time, src, dst string, dstPort uint16, syn, ack bool) testPacket {
	eth := ethernetLayer(layers.EthernetTypeIPv4)
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(src).To4(),
		DstIP:    net.ParseIP(dst).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: 49152,
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Seq:     1,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return testPacket{ts: ts, data: serializePacket(eth, ip, tcp)}
}

func tcp6Packet(ts time.Time, src, dst string, dstPort uint16, syn, ack bool) testPacket {
	eth := ethernetLayer(layers.EthernetTypeIPv6)
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
	}
	tcp := &layers.TCP{
		SrcPort: 49152,
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Seq:     1,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return testPacket{ts: ts, data: serializePacket(eth, ip, tcp)}
}

func udp4Packet(ts time.Time, src, dst string, dstPort uint16) testPacket {
	eth := ethernetLayer(layers.EthernetTypeIPv4)
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(src).To4(),
		DstIP:    net.ParseIP(dst).To4(),
	}
	udp := &layers.UDP{
		SrcPort: 49152,
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return testPacket{ts: ts, data: serializePacket(eth, ip, udp, gopacket.Payload([]byte{0x01}))}
}

func udp6Packet(ts time.Time, src, dst string, dstPort uint16) testPacket {
	eth := ethernetLayer(layers.EthernetTypeIPv6)
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
	}
	udp := &layers.UDP{
		SrcPort: 49152,
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return testPacket{ts: ts, data: serializePacket(eth, ip, udp, gopacket.Payload([]byte{0x01}))}
}

func ethernetLayer(ethernetType layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: ethernetType,
	}
}

func serializePacket(layersToSerialize ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func writePCAP(t *testing.T, packets []testPacket) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for _, packet := range packets {
		if err := w.WritePacket(captureInfo(packet), packet.data); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}
	return path
}

func writePCAPNG(t *testing.T, packets []testPacket) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcapng: %v", err)
	}
	defer f.Close()

	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("create pcapng writer: %v", err)
	}
	for _, packet := range packets {
		if err := w.WritePacket(captureInfo(packet), packet.data); err != nil {
			t.Fatalf("write pcapng packet: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush pcapng: %v", err)
	}
	return path
}

func captureInfo(packet testPacket) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp:     packet.ts,
		CaptureLength: len(packet.data),
		Length:        len(packet.data),
	}
}
