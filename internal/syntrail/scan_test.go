package syntrail

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
		Timestamp: ts.UTC(),
	}
	if records[0] != want {
		t.Fatalf("record = %+v, want %+v", records[0], want)
	}
	if records[0].Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", records[0].Timestamp.Location())
	}
}

func TestScanFilesExcludesNonMatchingPackets(t *testing.T) {
	ts := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	path := writePCAP(t, []testPacket{
		tcp4Packet(ts, "10.1.2.3", "203.0.113.10", 443, true, true),
		udp4Packet(ts.Add(time.Second), "10.1.2.3", "203.0.113.10", 443),
		tcp6Packet(ts.Add(2*time.Second), "fd00::1", "2001:db8::10", 443, true, false),
		tcp4Packet(ts.Add(3*time.Second), "198.51.100.20", "203.0.113.10", 443, true, false),
		tcp4Packet(ts.Add(4*time.Second), "10.1.2.3", "203.0.113.10", 0, true, false),
	})

	records, err := ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("ScanFiles() returned %d records, want 0: %+v", len(records), records)
	}
}

func TestScanFilesPreservesFileOrder(t *testing.T) {
	firstTS := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	secondTS := firstTS.Add(time.Second)

	first := writePCAP(t, []testPacket{
		tcp4Packet(firstTS, "10.0.0.1", "203.0.113.1", 443, true, false),
	})
	second := writePCAP(t, []testPacket{
		tcp4Packet(secondTS, "10.0.0.2", "203.0.113.2", 8443, true, false),
	})

	records, err := ScanFiles(context.Background(), []string{second, first})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ScanFiles() returned %d records, want 2", len(records))
	}

	if records[0].SrcIP != netip.MustParseAddr("10.0.0.2") || records[1].SrcIP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("records are out of file order: %+v", records)
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
