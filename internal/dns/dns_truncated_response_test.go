package dns

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestExtractDNSResponseFromRawSalvagesCompleteARecordFromCaptureTruncatedPacket(t *testing.T) {
	path := filepath.Join("testdata", "truncated_dns_response_cdn_samsung.pcap")
	packet := firstFixturePacket(t, path)
	ci := packet.Metadata().CaptureInfo
	if ci.CaptureLength >= ci.Length {
		t.Fatalf("fixture is not capture-truncated: capture length %d, wire length %d", ci.CaptureLength, ci.Length)
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("fixture packet has no UDP layer: %v", packet.Layers())
	}
	udp := udpLayer.(*layers.UDP)
	if uint16(udp.SrcPort) != 53 {
		t.Fatalf("fixture is not a DNS response from port 53: src port %d", udp.SrcPort)
	}

	id, qname, ips, _, ok := extractDNSResponseFromRaw(udp.Payload, L4ProtoUDP, true)
	if !ok {
		t.Fatalf("extractDNSResponseFromRaw() failed to salvage DNS response evidence")
	}

	t.Logf("salvaged DNS response id=%#x qname=%s ips=%v", id, qname, ips)

	if qname != "cdn.samsungcloudsolution.com" {
		t.Fatalf("qname = %q, want cdn.samsungcloudsolution.com", qname)
	}

	wantIP := "23.48.23.56"
	for _, ip := range ips {
		if ip.Equal(net.ParseIP(wantIP)) {
			return
		}
	}
	t.Fatalf("salvaged IPs %v do not contain %s", ips, wantIP)
}

func firstFixturePacket(t *testing.T, path string) gopacket.Packet {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	defer f.Close()

	source, err := fixturePacketSource(f)
	if err != nil {
		t.Fatalf("open fixture packet source: %v", err)
	}
	packet, err := source.NextPacket()
	if err != nil {
		t.Fatalf("read fixture packet: %v", err)
	}
	return packet
}

func fixturePacketSource(f *os.File) (*gopacket.PacketSource, error) {
	r := bufio.NewReader(f)
	magic, _ := r.Peek(4)
	if len(magic) == 4 && magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		ngr, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapng reader: %w", err)
		}
		return gopacket.NewPacketSource(ngr, ngr.LinkType()), nil
	}

	pr, err := pcapgo.NewReader(r)
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("pcap reader: %w", err)
	}
	return gopacket.NewPacketSource(pr, pr.LinkType()), nil
}
