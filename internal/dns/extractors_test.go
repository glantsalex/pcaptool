package dns

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestExtractTruncatedDNSQueryDiagnostic(t *testing.T) {
	header := func() []byte {
		msg := make([]byte, 12)
		binary.BigEndian.PutUint16(msg[0:2], 0x1234)
		binary.BigEndian.PutUint16(msg[2:4], 0x0100)
		binary.BigEndian.PutUint16(msg[4:6], 1)
		return msg
	}

	tests := []struct {
		name       string
		payload    []byte
		wantName   string
		wantReason string
		wantOK     bool
	}{
		{
			name:    "complete QNAME is not diagnostic",
			payload: buildRawDNSQuery("api.example", uint16(layers.DNSTypeA)),
		},
		{
			name:       "truncated in first label preserves visible bytes",
			payload:    append(header(), 0x07, 'E', 'x'),
			wantName:   "ex",
			wantReason: truncatedDNSReasonLabel,
			wantOK:     true,
		},
		{
			name:       "truncated after complete label preserves prefix",
			payload:    append(header(), 0x03, 'a', 'p', 'i', 0x07, 'e', 'x'),
			wantName:   "api.ex",
			wantReason: truncatedDNSReasonLabel,
			wantOK:     true,
		},
		{
			name:       "truncated before root label preserves visible name",
			payload:    append(header(), 0x03, 'A', 'P', 'I', 0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E'),
			wantName:   "api.example",
			wantReason: truncatedDNSReasonMissingRoot,
			wantOK:     true,
		},
		{
			name:    "shorter than DNS header is safe",
			payload: []byte{0x12, 0x34, 0x01},
		},
		{
			name:       "header ends before first label length",
			payload:    header(),
			wantReason: truncatedDNSReasonMissingRoot,
			wantOK:     true,
		},
		{
			name:       "compression pointer preserves prior labels",
			payload:    append(header(), 0x03, 'a', 'p', 'i', 0xc0, 0x0c),
			wantName:   "api",
			wantReason: truncatedDNSReasonCompressionPointer,
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, gotName, gotReason, gotOK := extractTruncatedDNSQueryDiagnostic(tt.payload)
			if gotOK != tt.wantOK || gotName != tt.wantName || gotReason != tt.wantReason {
				t.Fatalf(
					"extractTruncatedDNSQueryDiagnostic() = (%#x, %q, %q, %v), want (_, %q, %q, %v)",
					id,
					gotName,
					gotReason,
					gotOK,
					tt.wantName,
					tt.wantReason,
					tt.wantOK,
				)
			}
			if gotOK && id != 0x1234 {
				t.Fatalf("extractTruncatedDNSQueryDiagnostic() id = %#x, want 0x1234", id)
			}
		})
	}
}

func TestDNSExtractorCollectsTruncatedUDPQueryDiagnosticWithoutCreatingTransaction(t *testing.T) {
	raw := make([]byte, 12)
	binary.BigEndian.PutUint16(raw[0:2], 0x4321)
	binary.BigEndian.PutUint16(raw[2:4], 0x0100)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 0x03, 'a', 'p', 'i', 0x07, 'e', 'x')

	packet := gopacket.NewPacket(
		buildTestIPv4UDPPacket(t, raw),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	packet.Metadata().Timestamp = time.Date(2026, 6, 28, 10, 11, 12, 123, time.UTC)
	packet.Metadata().Truncated = true

	extractor := newDNSExtractorWithDiagnostics(true)
	extractor.OnPacket(packet, "captures/truncated.pcap")

	rows := extractor.TruncatedDNSPackets()
	if len(rows) != 1 {
		t.Fatalf("truncated diagnostics = %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.PCAPFile != "truncated.pcap" || row.IssuerIP != "10.0.0.10" || row.TruncatedDNSName != "api.ex" {
		t.Fatalf("unexpected truncated diagnostic: %+v", row)
	}
	if len(extractor.Map()) != 0 {
		t.Fatalf("diagnostic-only extraction created DNS transactions: %+v", extractor.Map())
	}
}

func TestDNSExtractorDoesNotCreateTransactionFromTruncatedQueryWhenDiagnosticsDisabled(t *testing.T) {
	raw := make([]byte, 12)
	binary.BigEndian.PutUint16(raw[0:2], 0x4321)
	binary.BigEndian.PutUint16(raw[2:4], 0x0100)
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw = append(raw, 0x03, 'a', 'p', 'i', 0x07, 'e', 'x')

	packet := gopacket.NewPacket(
		buildTestIPv4UDPPacket(t, raw),
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	packet.Metadata().Truncated = true

	extractor := newDNSExtractorWithDiagnostics(false)
	extractor.OnPacket(packet, "captures/truncated.pcap")

	if len(extractor.TruncatedDNSPackets()) != 0 {
		t.Fatalf("diagnostics-disabled extractor returned rows: %+v", extractor.TruncatedDNSPackets())
	}
	if len(extractor.Map()) != 0 {
		t.Fatalf("truncated query created DNS transactions: %+v", extractor.Map())
	}
}

func buildTestIPv4UDPPacket(t *testing.T, dnsPayload []byte) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.10").To4(),
		DstIP:    net.ParseIP("192.0.2.53").To4(),
	}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set UDP checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip4,
		udp,
		gopacket.Payload(dnsPayload),
	); err != nil {
		t.Fatalf("serialize test DNS packet: %v", err)
	}
	return buf.Bytes()
}
