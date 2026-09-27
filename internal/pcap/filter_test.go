package pcap

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestIPv4EndpointAdmission(t *testing.T) {
	members := map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.1"): {},
		netip.MustParseAddr("10.0.0.2"): {},
	}
	admit := IPv4EndpointAdmission(func(ip netip.Addr) bool {
		_, ok := members[ip]
		return ok
	})

	tests := []struct {
		name   string
		packet gopacket.Packet
		want   bool
	}{
		{name: "fleet source", packet: testIPv4Packet(t, "10.0.0.1", "192.0.2.1"), want: true},
		{name: "fleet destination", packet: testIPv4Packet(t, "192.0.2.1", "10.0.0.1"), want: true},
		{name: "fleet to fleet", packet: testIPv4Packet(t, "10.0.0.1", "10.0.0.2"), want: true},
		{name: "neither endpoint", packet: testIPv4Packet(t, "192.0.2.1", "198.51.100.1"), want: false},
		{name: "IPv6", packet: testIPv6Packet(t), want: false},
		{name: "non IP", packet: testARPFrame(t), want: false},
		{name: "nil packet", packet: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := admit(tt.packet); got != tt.want {
				t.Fatalf("admission = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv4EndpointAdmissionNilMembershipRejectsAll(t *testing.T) {
	if IPv4EndpointAdmission(nil)(testIPv4Packet(t, "10.0.0.1", "10.0.0.2")) {
		t.Fatal("nil membership function admitted a packet")
	}
}

func testIPv4Packet(t *testing.T, src, dst string) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(src).To4(),
		DstIP:    net.ParseIP(dst).To4(),
	}
	udp := &layers.UDP{SrcPort: 10000, DstPort: 10001}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}
	return serializeTestPacket(t, eth, ip, udp)
}

func testIPv6Packet(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	udp := &layers.UDP{SrcPort: 10000, DstPort: 10001}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}
	return serializeTestPacket(t, eth, ip, udp)
}

func testARPFrame(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0, 1, 2, 3, 4, 5},
		SourceProtAddress: []byte{10, 0, 0, 1},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte{10, 0, 0, 2},
	}
	return serializeTestPacket(t, eth, arp)
}

func serializeTestPacket(t *testing.T, packetLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		packetLayers...,
	); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
