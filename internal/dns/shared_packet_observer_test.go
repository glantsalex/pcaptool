package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func TestLibpcapMixedInterfaceReadErrorAdvancesToNextCompatiblePacket(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "mixed-interfaces.pcapng")
	writeSharedObserverMixedInterfacePCAPNG(
		t,
		path,
		dnsAdmissionPacket{ts: base, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		dnsAdmissionPacket{ts: base.Add(time.Second), data: []byte{0x45, 0, 0, 20}},
		dnsAdmissionPacket{ts: base.Add(2 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.2", "203.0.113.11", 40000, 8443, true, false)},
	)

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	var (
		ports      []uint16
		readErrors int
		reachedEOF bool
	)
	for attempt := 1; attempt <= 10; attempt++ {
		packet, err := source.NextPacket()
		if errors.Is(err, io.EOF) {
			reachedEOF = true
			break
		}
		if err != nil {
			readErrors++
			continue
		}
		if packet != nil {
			if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
				ports = append(ports, uint16(tcp.DstPort))
			}
		}
	}
	if !reachedEOF {
		t.Fatal("libpcap did not reach EOF within bounded mixed-interface reads")
	}
	if readErrors == 0 {
		t.Fatal("mixed-interface PCAPNG produced no libpcap compatibility read error")
	}
	if want := []uint16{443, 8443}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("compatible packet ports across libpcap errors = %v, want %v", ports, want)
	}
}

func TestSharedPacketObserverMatchesLegacyFleetScanAcrossClassicPCAPPrecisionsAndFilters(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	pcapPath := filepath.Join(t.TempDir(), "first.pcap")
	writeConnectionAdmissionPCAP(t, pcapPath, []dnsAdmissionPacket{
		{ts: base.Add(5 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		{ts: base.Add(6 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		{ts: base.Add(7 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.11", 40000, 53, true, false)},
		{ts: base.Add(8 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.12", 40000, 8443, true, true)},
		{ts: base.Add(9 * time.Second), data: buildSharedObserverUDP(t, "10.0.0.1", "203.0.113.20", 40000, 5353)},
		{ts: base.Add(10 * time.Second), data: buildSharedObserverUDP(t, "192.168.1.1", "203.0.113.99", 40000, 5353)},
	})
	nanosPath := filepath.Join(t.TempDir(), "second.pcap")
	writeSharedObserverNanosPCAP(t, nanosPath, []dnsAdmissionPacket{
		{ts: base.Add(2 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.2", "203.0.113.13", 40000, 9443, true, false)},
		{ts: base, data: buildSharedObserverUDP(t, "10.0.0.1", "203.0.113.20", 40000, 5353)},
		{ts: base.Add(time.Second), data: buildSharedObserverUDP(t, "10.0.0.2", "203.0.113.21", 40000, 123)},
	})
	files := []string{pcapPath, nanosPath}
	admit := func(packet gopacket.Packet) bool {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return false
		}
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String() != "192.168.1.1"
	}

	want, err := syntrail.ScanFilesWithOptions(context.Background(), files, syntrail.ScanOptions{
		Workers:         2,
		PacketAdmission: admit,
	})
	if err != nil {
		t.Fatalf("legacy fleet scan: %v", err)
	}

	accumulator := syntrail.NewAccumulator()
	_, _, err = AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(),
		files,
		nil,
		true,
		false,
		map[uint16]struct{}{443: {}},
		true,
		nil,
		nil,
		0,
		PacketScanOptions{
			PacketAdmission: admit,
			NewFileObserver: func(_ int, _ string) PacketFileObserver {
				collector := syntrail.NewCollector()
				return PacketFileObserver{
					Observe: collector.Observe,
					Commit:  func() { accumulator.Add(collector.TakeRecords()) },
				}
			},
		},
	)
	if err != nil {
		t.Fatalf("shared connection/fleet scan: %v", err)
	}
	got := accumulator.TakeRecords()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shared records = %+v, want legacy %+v", got, want)
	}
	if len(got) < 4 || got[3].DstPort != 9443 || got[3].Timestamp.Nanosecond() != 123456789 {
		t.Fatalf("nanosecond-resolution PCAP timestamp precision changed: %+v", got)
	}
}

func TestSharedPacketObserverMatchesLegacySingleInterfacePCAPNGWithoutRecovery(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	writeSharedObserverPCAPNG(t, path, []dnsAdmissionPacket{
		{ts: base, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)},
		{ts: base.Add(time.Second), data: buildSharedObserverUDP(t, "10.0.0.1", "203.0.113.20", 40000, 5353)},
	})
	want, err := syntrail.ScanFiles(context.Background(), []string{path})
	if err != nil {
		t.Fatal(err)
	}

	accumulator := syntrail.NewAccumulator()
	readErrors := 0
	_, _, err = AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{NewFileObserver: func(_ int, _ string) PacketFileObserver {
			collector := syntrail.NewCollector()
			return PacketFileObserver{
				Observe: collector.Observe,
				OnReadError: func(context.Context, error) error {
					readErrors++
					return nil
				},
				Commit: func() { accumulator.Add(collector.TakeRecords()) },
			}
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if readErrors != 0 {
		t.Fatalf("ordinary PCAPNG compatibility rereads = %d, want 0", readErrors)
	}
	if got := accumulator.TakeRecords(); !reflect.DeepEqual(got, want) {
		t.Fatalf("shared ordinary PCAPNG records = %+v, want %+v", got, want)
	}
}

func TestSharedPacketObserverReturnsTruncatedCaptureReadErrorWithoutCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncated.pcap")
	writeConnectionAdmissionPCAP(t, path, []dnsAdmissionPacket{{
		ts:   time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false),
	}})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-1); err != nil {
		t.Fatal(err)
	}

	committed := false
	_, _, err = AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{NewFileObserver: func(_ int, _ string) PacketFileObserver {
			return PacketFileObserver{Commit: func() { committed = true }}
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "read packet from") || !strings.Contains(err.Error(), path) {
		t.Fatalf("shared scan error = %v, want path-contextual read error", err)
	}
	if committed {
		t.Fatal("observer committed partial records after capture read error")
	}
}

func TestSharedPacketObserverCancellationDoesNotCommitPartialRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.pcap")
	packet := buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40000, 443, true, false)
	packets := make([]dnsAdmissionPacket, 100)
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for i := range packets {
		packets[i] = dnsAdmissionPacket{ts: base.Add(time.Duration(i) * time.Millisecond), data: packet}
	}
	writeConnectionAdmissionPCAP(t, path, packets)

	ctx, cancel := context.WithCancel(context.Background())
	committed := false
	seen := 0
	_, _, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		ctx, []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{NewFileObserver: func(_ int, _ string) PacketFileObserver {
			return PacketFileObserver{
				Observe: func(gopacket.Packet) {
					seen++
					if seen == 5 {
						cancel()
					}
				},
				Commit: func() { committed = true },
			}
		}},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("shared scan error = %v, want context.Canceled", err)
	}
	if committed {
		t.Fatal("observer committed partial records after cancellation")
	}
}

func buildSharedObserverUDP(t *testing.T, src, dst string, srcPort, dstPort uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload{1}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeSharedObserverNanosPCAP(t *testing.T, path string, packets []dnsAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatal(err)
	}
	for _, packet := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: packet.ts, CaptureLength: len(packet.data), Length: len(packet.data)}, packet.data); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeSharedObserverPCAPNG(t *testing.T, path string, packets []dnsAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	for _, packet := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: packet.ts, CaptureLength: len(packet.data), Length: len(packet.data)}, packet.data); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeSharedObserverMixedInterfacePCAPNG(t *testing.T, path string, ethernetBefore, raw, ethernetAfter dnsAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	rawInterface, err := w.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeRaw, SnapLength: 65535})
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	for _, packet := range []struct {
		dnsAdmissionPacket
		interfaceIndex int
	}{
		{dnsAdmissionPacket: ethernetBefore},
		{dnsAdmissionPacket: raw, interfaceIndex: rawInterface},
		{dnsAdmissionPacket: ethernetAfter},
	} {
		ci := gopacket.CaptureInfo{
			Timestamp: packet.ts, CaptureLength: len(packet.data), Length: len(packet.data), InterfaceIndex: packet.interfaceIndex,
		}
		if err := w.WritePacket(ci, packet.data); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
