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

func TestCollector_EdgesByFirstSeenOrdersNaturally(t *testing.T) {
	opt := DefaultOptions()
	c := NewCollector(opt)

	ts := time.Unix(1700000200, 0).UTC()

	// First endpoint: tcp/443
	c.OnPacket(mustPacketIPv4TCP(t, "10.0.0.9", "80.80.80.80", 50000, 443, true, false), ts)
	c.OnPacket(mustPacketIPv4TCP(t, "80.80.80.80", "10.0.0.9", 443, 50000, true, true), ts.Add(10*time.Millisecond))

	// Second endpoint: tcp/8443
	c.OnPacket(mustPacketIPv4TCP(t, "10.0.0.9", "81.81.81.81", 50001, 8443, true, false), ts.Add(1*time.Second))
	c.OnPacket(mustPacketIPv4TCP(t, "81.81.81.81", "10.0.0.9", 8443, 50001, true, true), ts.Add(1010*time.Millisecond))

	edges := c.EdgesByFirstSeen()
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %#v", edges)
	}
	if edges[0].Port != 443 || edges[1].Port != 8443 {
		t.Fatalf("expected first-seen order 443 then 8443, got %#v", edges)
	}
}

func TestCollector_FTPPassiveReplySuppressesExactDataPort(t *testing.T) {
	opt := DefaultOptions()
	opt.FTPPassiveMinPort = 30000
	c := NewCollector(opt)

	ts := time.Unix(1700000300, 0).UTC()

	// Control channel to FTP server.
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21, true, false, nil), ts)
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21, 35762, true, true, nil), ts.Add(10*time.Millisecond))

	// FTP passive negotiation on control channel.
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21, false, true, []byte("PASV\r\n")), ts.Add(20*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21, 35762, false, true, []byte("227 Entering Passive Mode (185,5,124,52,8,174)\r\n")), ts.Add(30*time.Millisecond))

	// Data channel to announced passive port 2222 should be suppressed even though
	// it is below the heuristic FTP passive threshold.
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35763, 2222, true, false, nil), ts.Add(40*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 2222, 35763, true, true, nil), ts.Add(50*time.Millisecond))

	// Unannounced low port should still appear.
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35764, 2223, true, false, nil), ts.Add(60*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 2223, 35764, true, true, nil), ts.Add(70*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 2 {
		t.Fatalf("expected ftp control edge and one non-passive edge, got %#v", edges)
	}
	if edges[0].Port != 21 || edges[1].Port != 2223 {
		t.Fatalf("expected ports 21 and 2223 only, got %#v", edges)
	}
}

func TestCollector_FTPEPSVReplySuppressesExactDataPort(t *testing.T) {
	opt := DefaultOptions()
	opt.FTPPassiveMinPort = 30000
	c := NewCollector(opt)

	ts := time.Unix(1700000400, 0).UTC()

	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21, true, false, nil), ts)
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21, 35762, true, true, nil), ts.Add(10*time.Millisecond))

	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21, false, true, []byte("EPSV\r\n")), ts.Add(20*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21, 35762, false, true, []byte("229 Entering Extended Passive Mode (|||2121|)\r\n")), ts.Add(30*time.Millisecond))

	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35763, 2121, true, false, nil), ts.Add(40*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 2121, 35763, true, true, nil), ts.Add(50*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 1 || edges[0].Port != 21 {
		t.Fatalf("expected only ftp control edge after EPSV suppression, got %#v", edges)
	}
}

func mustPacketIPv4TCP(t *testing.T, srcIP string, dstIP string, srcPort uint16, dstPort uint16, syn bool, ack bool) gopacket.Packet {
	t.Helper()
	return mustPacketIPv4TCPWithPayload(t, srcIP, dstIP, srcPort, dstPort, syn, ack, nil)
}

func mustPacketIPv4TCPWithPayload(t *testing.T, srcIP string, dstIP string, srcPort uint16, dstPort uint16, syn bool, ack bool, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    parseIPv4(t, srcIP),
		DstIP:    parseIPv4(t, dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set tcp checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
