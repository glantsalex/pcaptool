package connectivity

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func mustPacketIPv4UDP(t *testing.T, srcIP string, dstIP string, srcPort uint16, dstPort uint16) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    parseIPv4(t, srcIP),
		DstIP:    parseIPv4(t, dstIP),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set udp checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload([]byte{0x01})); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func parseIPv4(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("invalid IPv4 %q", s)
	}
	return ip.To4()
}

func TestCollector_UDPExcludedPortSymmetric(t *testing.T) {
	opt := DefaultOptions()
	opt.ExcludedDstPorts = map[uint16]struct{}{
		123: {},
	}
	c := NewCollector(opt)

	ts := time.Unix(1700000000, 0).UTC()

	// Reply seen first (public:123 -> private:ephemeral), then request.
	p1 := mustPacketIPv4UDP(t, "216.239.35.4", "10.22.111.161", 123, 41811)
	p2 := mustPacketIPv4UDP(t, "10.22.111.161", "216.239.35.4", 41811, 123)

	c.OnPacket(p1, ts)
	c.OnPacket(p2, ts.Add(10*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 0 {
		t.Fatalf("expected no UDP edges for excluded port 123, got %#v", edges)
	}
}

func TestCollector_UDPNonExcludedPortStillEmitted(t *testing.T) {
	opt := DefaultOptions()
	opt.ExcludedDstPorts = map[uint16]struct{}{
		123: {},
	}
	c := NewCollector(opt)

	ts := time.Unix(1700000100, 0).UTC()

	// Non-excluded UDP pair (e.g. app on 3000).
	p1 := mustPacketIPv4UDP(t, "10.22.111.161", "54.154.187.160", 50234, 3000)
	p2 := mustPacketIPv4UDP(t, "54.154.187.160", "10.22.111.161", 3000, 50234)

	c.OnPacket(p1, ts)
	c.OnPacket(p2, ts.Add(10*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 1 {
		t.Fatalf("expected one UDP edge, got %#v", edges)
	}
	if edges[0].Port != 3000 {
		t.Fatalf("expected service port 3000, got %d", edges[0].Port)
	}
}
