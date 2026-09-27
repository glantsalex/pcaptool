package radius

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pcaputil "github.com/aglants/pcaptool/internal/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestProcessRadiusFilePacketAdmissionFiltersBeforeEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "radius.pcap")
	packets := []radiusAdmissionPacket{
		{src: "192.168.1.10", dst: "192.168.1.20", imsi: "123456789012345", framedIP: "10.10.10.10", sessionID: "excluded"},
	}
	// processRadiusFile flushes evidence to its shared collector in batches of
	// 256, so provide one full retained batch after the excluded packet.
	for i := 0; i < 256; i++ {
		packet := radiusAdmissionPacket{
			src:       "10.0.0.1",
			dst:       "192.168.1.20",
			imsi:      "223456789012345",
			framedIP:  "10.10.10.20",
			sessionID: "retained-" + strconv.Itoa(i),
		}
		if i%2 == 1 {
			packet.src, packet.dst = "192.168.1.20", "10.0.0.2"
		}
		packets = append(packets, packet)
	}
	writeRadiusAdmissionPCAP(t, path, packets)

	unfiltered := collectRadiusMessages(t, path, nil)
	if len(unfiltered) != 256 || unfiltered[0].sid != "excluded" {
		t.Fatalf("unfiltered RADIUS batch = %d messages, first session %q; want 256/excluded", len(unfiltered), unfiltered[0].sid)
	}

	fleet := map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.1"): {},
		netip.MustParseAddr("10.0.0.2"): {},
	}
	admit := pcaputil.IPv4EndpointAdmission(func(ip netip.Addr) bool {
		_, ok := fleet[ip]
		return ok
	})
	filtered := collectRadiusMessages(t, path, admit)
	if len(filtered) != 256 {
		t.Fatalf("filtered RADIUS messages = %d, want 256", len(filtered))
	}
	for _, message := range filtered {
		if !strings.HasPrefix(message.sid, "retained-") {
			t.Fatalf("excluded RADIUS evidence leaked through packet admission: %+v", message)
		}
	}
}

func collectRadiusMessages(t *testing.T, path string, admit pcaputil.PacketAdmission) []radMsg {
	t.Helper()
	collector := NewRadiusCollector(4)
	if err := processRadiusFile(context.Background(), path, collector, newDeduper(time.Hour, 1), admit); err != nil {
		t.Fatalf("processRadiusFile(%q): %v", path, err)
	}
	return collector.Drain()
}

type radiusAdmissionPacket struct {
	src       string
	dst       string
	imsi      string
	framedIP  string
	sessionID string
}

func writeRadiusAdmissionPCAP(t *testing.T, path string, packets []radiusAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create RADIUS pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatalf("write RADIUS pcap header: %v", err)
	}
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for i, packet := range packets {
		data := buildRadiusAdmissionPacket(t, packet, byte(i+1))
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp: base.Add(time.Duration(i) * time.Second), CaptureLength: len(data), Length: len(data),
		}, data); err != nil {
			f.Close()
			t.Fatalf("write RADIUS pcap packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close RADIUS pcap: %v", err)
	}
}

func buildRadiusAdmissionPacket(t *testing.T, packet radiusAdmissionPacket, identifier byte) []byte {
	t.Helper()
	attribute := func(typ byte, value []byte) []byte {
		return append([]byte{typ, byte(len(value) + 2)}, value...)
	}
	payload := make([]byte, 20)
	payload[0] = byte(layers.RADIUSCodeAccountingRequest)
	payload[1] = identifier
	payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeUserName), []byte(packet.imsi))...)
	payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeFramedIPAddress), net.ParseIP(packet.framedIP).To4())...)
	payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeAcctStatusType), []byte{0, 0, 0, 1})...)
	payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeAcctSessionId), []byte(packet.sessionID))...)
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(packet.src).To4(), DstIP: net.ParseIP(packet.dst).To4(),
	}
	udp := &layers.UDP{SrcPort: 1813, DstPort: 1813}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set RADIUS UDP checksum layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize RADIUS packet: %v", err)
	}
	return buf.Bytes()
}
