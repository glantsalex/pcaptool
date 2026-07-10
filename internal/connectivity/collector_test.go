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

func TestCollector_EdgesRetainBoundedRepeatedObservations(t *testing.T) {
	opt := DefaultOptions()
	c := NewCollector(opt)

	ts := time.Unix(1700000250, 0).UTC()

	c.OnPacket(mustPacketIPv4TCP(t, "10.0.0.9", "80.80.80.80", 50000, 443, true, false), ts)
	c.OnPacket(mustPacketIPv4TCP(t, "80.80.80.80", "10.0.0.9", 443, 50000, true, true), ts.Add(10*time.Millisecond))

	later := ts.Add(2 * time.Minute)
	c.OnPacket(mustPacketIPv4TCP(t, "10.0.0.9", "80.80.80.80", 50001, 443, true, false), later)
	c.OnPacket(mustPacketIPv4TCP(t, "80.80.80.80", "10.0.0.9", 443, 50001, true, true), later.Add(10*time.Millisecond))

	edges := c.EdgesByFirstSeen()
	if len(edges) != 1 {
		t.Fatalf("expected one endpoint edge, got %#v", edges)
	}
	if !edges[0].FirstSeen.Equal(ts) {
		t.Fatalf("expected first seen %s, got %s", ts, edges[0].FirstSeen)
	}
	if len(edges[0].ObservedTimes) != 2 {
		t.Fatalf("expected two observed times, got %#v", edges[0].ObservedTimes)
	}
	if !edges[0].ObservedTimes[0].Equal(ts) || !edges[0].ObservedTimes[1].Equal(later) {
		t.Fatalf("unexpected observed times: %#v", edges[0].ObservedTimes)
	}
}

func TestMergeEdgeObservedTimesKeepsFirstAndLatestWithinBound(t *testing.T) {
	base := time.Unix(1700000275, 0).UTC()
	var additions []time.Time
	for i := 0; i < maxEdgeObservedTimes+10; i++ {
		additions = append(additions, base.Add(time.Duration(i)*time.Second))
	}

	got := MergeEdgeObservedTimes(nil, additions...)
	if len(got) != maxEdgeObservedTimes {
		t.Fatalf("expected %d bounded observations, got %d", maxEdgeObservedTimes, len(got))
	}
	if !got[0].Equal(base) {
		t.Fatalf("expected first observation to be preserved, got %s", got[0])
	}
	wantLatest := base.Add(time.Duration(maxEdgeObservedTimes+9) * time.Second)
	if !got[len(got)-1].Equal(wantLatest) {
		t.Fatalf("expected latest observation %s to be preserved, got %s", wantLatest, got[len(got)-1])
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

func TestCollector_DefaultFTPSControlPortSuppressesHighDataPort(t *testing.T) {
	c := NewCollector(DefaultOptions())
	ts := time.Unix(1700000500, 0).UTC()

	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35762, 990, true, false), ts)
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 990, 35762, true, true), ts.Add(10*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35763, 40000, true, false), ts.Add(20*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 40000, 35763, true, true), ts.Add(30*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 1 || edges[0].Port != 990 {
		t.Fatalf("expected only default FTPS control edge, got %#v", edges)
	}
}

func TestCollector_FTPPassiveMinPortDefaultAndCustomValue(t *testing.T) {
	tests := []struct {
		name           string
		minPassivePort uint16
		keptDataPort   uint16
		suppressedPort uint16
	}{
		{
			name:           "zero uses default",
			minPassivePort: 0,
			keptDataPort:   29999,
			suppressedPort: 30000,
		},
		{
			name:           "nonzero uses exact value",
			minPassivePort: 40000,
			keptDataPort:   39999,
			suppressedPort: 40000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := DefaultOptions()
			opt.FTPPassiveMinPort = tt.minPassivePort
			c := NewCollector(opt)
			ts := time.Unix(1700000550, 0).UTC()

			c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35762, 21, true, false), ts)
			c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 21, 35762, true, true), ts.Add(10*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35763, tt.keptDataPort, true, false), ts.Add(20*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", tt.keptDataPort, 35763, true, true), ts.Add(30*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35764, tt.suppressedPort, true, false), ts.Add(40*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", tt.suppressedPort, 35764, true, true), ts.Add(50*time.Millisecond))

			edges := c.Edges()
			if len(edges) != 2 {
				t.Fatalf("expected control and below-threshold edges, got %#v", edges)
			}
			if edges[0].Port != 21 || edges[1].Port != tt.keptDataPort {
				t.Fatalf("expected ports 21 and %d, got %#v", tt.keptDataPort, edges)
			}
		})
	}
}

func TestCollector_FTPCustomControlAndPassiveMinimumWorkTogether(t *testing.T) {
	tests := []struct {
		name           string
		minPassivePort uint16
		wantDataEdge   bool
	}{
		{name: "data port at or above minimum is suppressed", minPassivePort: 16000},
		{name: "data port below minimum is retained", minPassivePort: 17000, wantDataEdge: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := DefaultOptions()
			opt.FTPControlPorts = map[uint16]struct{}{21000: {}}
			opt.FTPPassiveMinPort = tt.minPassivePort
			c := NewCollector(opt)
			ts := time.Unix(1700000575, 0).UTC()

			c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35762, 21000, true, false), ts)
			c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 21000, 35762, true, true), ts.Add(10*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35763, 16279, true, false), ts.Add(20*time.Millisecond))
			c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 16279, 35763, true, true), ts.Add(30*time.Millisecond))

			edges := c.Edges()
			wantEdges := 1
			if tt.wantDataEdge {
				wantEdges = 2
			}
			if len(edges) != wantEdges {
				t.Fatalf("expected %d edges, got %#v", wantEdges, edges)
			}
			gotPorts := make(map[uint16]struct{}, len(edges))
			for _, edge := range edges {
				gotPorts[edge.Port] = struct{}{}
			}
			if _, ok := gotPorts[21000]; !ok {
				t.Fatalf("expected custom control edge, got %#v", edges)
			}
			_, gotDataEdge := gotPorts[16279]
			if gotDataEdge != tt.wantDataEdge {
				t.Fatalf("expected below-threshold data edge, got %#v", edges)
			}
		})
	}
}

func TestCollector_CustomFTPControlPortSuppressesExactAndHighDataPorts(t *testing.T) {
	opt := DefaultOptions()
	opt.FTPControlPorts = map[uint16]struct{}{21000: {}}
	c := NewCollector(opt)
	ts := time.Unix(1700000600, 0).UTC()

	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21000, true, false, nil), ts)
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21000, 35762, true, true, nil), ts.Add(10*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "10.119.163.201", "185.5.124.52", 35762, 21000, false, true, []byte("PASV\r\n")), ts.Add(20*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCPWithPayload(t, "185.5.124.52", "10.119.163.201", 21000, 35762, false, true, []byte("227 Entering Passive Mode (185,5,124,52,8,174)\r\n")), ts.Add(30*time.Millisecond))

	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35763, 2222, true, false), ts.Add(40*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 2222, 35763, true, true), ts.Add(50*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35764, 40000, true, false), ts.Add(60*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 40000, 35764, true, true), ts.Add(70*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 1 || edges[0].Port != 21000 {
		t.Fatalf("expected only custom ftp control edge, got %#v", edges)
	}
}

func TestCollector_FTPControlPortsAreCopiedAndReplaceDefaults(t *testing.T) {
	controlPorts := map[uint16]struct{}{21000: {}}
	opt := DefaultOptions()
	opt.FTPControlPorts = controlPorts
	c := NewCollector(opt)

	delete(controlPorts, 21000)
	controlPorts[21] = struct{}{}

	ts := time.Unix(1700000700, 0).UTC()

	// Port 21 was added after collector construction and must not become a control port.
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35762, 21, true, false), ts)
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 21, 35762, true, true), ts.Add(10*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "185.5.124.52", 35763, 40000, true, false), ts.Add(20*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "185.5.124.52", "10.119.163.201", 40000, 35763, true, true), ts.Add(30*time.Millisecond))

	// Port 21000 was removed after construction and must remain a control port.
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "194.30.98.208", 35764, 21000, true, false), ts.Add(40*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "194.30.98.208", "10.119.163.201", 21000, 35764, true, true), ts.Add(50*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "10.119.163.201", "194.30.98.208", 35765, 40001, true, false), ts.Add(60*time.Millisecond))
	c.OnPacket(mustPacketIPv4TCP(t, "194.30.98.208", "10.119.163.201", 40001, 35765, true, true), ts.Add(70*time.Millisecond))

	edges := c.Edges()
	if len(edges) != 3 {
		t.Fatalf("expected port 21 pair unsuppressed and port 21000 pair suppressed, got %#v", edges)
	}
	if edges[0].Port != 21 || edges[1].Port != 40000 || edges[2].Port != 21000 {
		t.Fatalf("expected ports 21, 40000, 21000, got %#v", edges)
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
