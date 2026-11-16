package radius

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestProcessRadiusFileRetainsAllAccountingAndPartialBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "radius.pcap")
	packets := []radiusAdmissionPacket{
		{src: "192.168.1.10", dst: "192.168.1.20", imsi: "123456789012345", framedIP: "10.10.10.10", sessionID: "excluded"},
	}
	// One full batch followed by a partial batch must retain every record.
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

	unfiltered := collectRadiusMessages(t, path)
	if len(unfiltered) != 257 || unfiltered[0].sid != "excluded" {
		t.Fatalf("unfiltered RADIUS batch = %d messages, first session %q; want 257/excluded", len(unfiltered), unfiltered[0].sid)
	}

}

func collectRadiusMessages(t *testing.T, path string) []radMsg {
	t.Helper()
	collector := NewRadiusCollector(4)
	if err := processRadiusFile(context.Background(), path, collector); err != nil {
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
	status    uint32
	duration  *uint32
	ts        time.Time
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
			Timestamp: packetTime(packet, base.Add(time.Duration(i)*time.Second)), CaptureLength: len(data), Length: len(data),
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
	status := packet.status
	if status == 0 {
		status = acctStatusStart
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, status)
	payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeAcctStatusType), value)...)
	if packet.duration != nil {
		value = make([]byte, 4)
		binary.BigEndian.PutUint32(value, *packet.duration)
		payload = append(payload, attribute(byte(layers.RADIUSAttributeTypeAcctSessionTime), value)...)
	}
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

func packetTime(p radiusAdmissionPacket, fallback time.Time) time.Time {
	if !p.ts.IsZero() {
		return p.ts
	}
	return fallback
}
