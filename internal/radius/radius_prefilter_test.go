package radius

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type prefilterTestPacket struct {
	data []byte
	info gopacket.CaptureInfo
}
type prefilterTestSource struct {
	packets   []prefilterTestPacket
	index     int
	terminal  error
	afterRead func()
}

func (s *prefilterTestSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if s.index == len(s.packets) {
		if s.terminal != nil {
			return nil, gopacket.CaptureInfo{}, s.terminal
		}
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	p := s.packets[s.index]
	s.index++
	if s.afterRead != nil {
		s.afterRead()
	}
	return p.data, p.info, nil
}
func prefilterInfo(data []byte, at time.Time) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(data), Length: len(data)}
}
func prefilterAccounting(t *testing.T) []byte {
	t.Helper()
	return buildRadiusAdmissionPacket(t, radiusAdmissionPacket{src: "192.0.2.1", dst: "192.0.2.2", framedIP: "10.0.0.1", imsi: "123456789012345", sessionID: "prefilter", status: acctStatusStart}, 1)
}
func prefilterVLAN(data []byte, tags ...uint16) []byte {
	out := append([]byte{}, data[:12]...)
	for _, tag := range tags {
		out = append(out, byte(tag>>8), byte(tag), 0, 7)
	}
	return append(out, data[12:]...)
}
func prefilterUDPPorts(data []byte, src, dst uint16) []byte {
	out := append([]byte{}, data...)
	binary.BigEndian.PutUint16(out[34:36], src)
	binary.BigEndian.PutUint16(out[36:38], dst)
	return out
}
func prefilterIPv6(t *testing.T, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &layers.UDP{SrcPort: 1813, DstPort: 1813}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv6}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Mirror the existing acceptance checks only, as an independent false-negative
// oracle. The complete data-model comparison is performed by the saved baseline.
func legacyAcceptsRadius(data []byte, link layers.LinkType) bool {
	pkt := gopacket.NewPacket(data, link, gopacket.Default)
	netL, transL := pkt.NetworkLayer(), pkt.TransportLayer()
	if netL == nil || transL == nil {
		return false
	}
	udp, ok := transL.(*layers.UDP)
	if !ok || !(isRadiusPort(udp.SrcPort) || isRadiusPort(udp.DstPort)) {
		return false
	}
	var rad layers.RADIUS
	decoded := []gopacket.LayerType{}
	if gopacket.NewDecodingLayerParser(layers.LayerTypeRADIUS, &rad).DecodeLayers(udp.Payload, &decoded) != nil || rad.Code != layers.RADIUSCodeAccountingRequest {
		return false
	}
	ip, imsi := extractIPAndIMSI(&rad)
	if ip == "" || imsi == "" || net.ParseIP(ip) == nil {
		return false
	}
	_, _, _, _, ok = extractStatusAndSessionID(&rad)
	return ok
}

func TestRadiusPrefilterLayoutsAndPorts(t *testing.T) {
	accounting := prefilterAccounting(t)
	otherUDP := prefilterUDPPorts(accounting, 53, 40000)
	tcp := append([]byte{}, otherUDP...)
	tcp[23] = byte(layers.IPProtocolTCP)
	ipv6 := prefilterIPv6(t, accounting[42:])
	ext := append([]byte{}, ipv6[:54]...)
	ext[20] = 0
	binary.BigEndian.PutUint16(ext[18:20], uint16(len(ipv6)-54+8))
	ext = append(ext, 17, 0, 1, 4, 0, 0, 0, 0)
	ext = append(ext, ipv6[54:]...)
	tunnel := append([]byte{}, accounting[:34]...)
	tunnel[23] = 4
	tunnel = append(tunnel, accounting[14:]...)
	binary.BigEndian.PutUint16(tunnel[16:18], uint16(len(tunnel)-14))
	fragment := append([]byte{}, accounting...)
	fragment[20] = 0x20
	options := append([]byte{}, accounting[:34]...)
	options[14] = 0x46
	options = append(options, 1, 1, 1, 0)
	options = append(options, accounting[34:]...)
	binary.BigEndian.PutUint16(options[16:18], uint16(len(options)-14))
	zeroLength := append([]byte{}, accounting...)
	zeroLength[16] = 0
	zeroLength[17] = 0
	tests := []struct {
		name                     string
		data                     []byte
		link                     layers.LinkType
		reject, fallback, legacy bool
	}{
		{"radius", accounting, layers.LinkTypeEthernet, false, false, true},
		{"dns", otherUDP, layers.LinkTypeEthernet, true, false, false},
		{"tcp", tcp, layers.LinkTypeEthernet, true, false, false},
		{"vlan radius", prefilterVLAN(accounting, 0x8100), layers.LinkTypeEthernet, false, false, true},
		{"qinq radius", prefilterVLAN(accounting, 0x88a8, 0x8100), layers.LinkTypeEthernet, false, false, true},
		{"double 8021q", prefilterVLAN(accounting, 0x8100, 0x8100), layers.LinkTypeEthernet, false, false, true},
		{"vlan tcp", prefilterVLAN(tcp, 0x8100), layers.LinkTypeEthernet, true, false, false},
		{"qinq dns", prefilterVLAN(otherUDP, 0x88a8, 0x8100), layers.LinkTypeEthernet, true, false, false},
		{"triple vlan", prefilterVLAN(accounting, 0x8100, 0x8100, 0x8100), layers.LinkTypeEthernet, false, true, true},
		{"ipv4 options", options, layers.LinkTypeEthernet, false, false, true},
		{"ipv6", ipv6, layers.LinkTypeEthernet, false, true, true},
		{"ipv6 extension", ext, layers.LinkTypeEthernet, false, true, true},
		{"ip tunnel", tunnel, layers.LinkTypeEthernet, false, true, true},
		{"fragment", fragment, layers.LinkTypeEthernet, false, true, false},
		{"raw ipv4", accounting[14:], layers.LinkTypeRaw, false, true, true},
		{"zero ip length", zeroLength, layers.LinkTypeEthernet, false, true, true},
		{"short ethernet", accounting[:8], layers.LinkTypeEthernet, false, true, false},
		{"empty", nil, layers.LinkTypeEthernet, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Unix(100, 123)
			ci := prefilterInfo(tc.data, at)
			ci.InterfaceIndex = 4
			ci.Length += 100 // Preserve truncation metadata.
			s := &prefilterTestSource{packets: []prefilterTestPacket{{tc.data, ci}}}
			var end time.Time
			r := newRadiusPacketSource(context.Background(), s, tc.link, &end, compileRadiusBPF)
			data, gotInfo, err := r.ReadPacketData()
			if tc.reject {
				if err != io.EOF || r.stats.rejected != 1 {
					t.Fatalf("did not reject: %v %+v", err, r.stats)
				}
			} else if err != nil || !reflect.DeepEqual(data, tc.data) || !reflect.DeepEqual(ci, gotInfo) {
				t.Fatalf("altered admitted packet: %v", err)
			}
			if !end.Equal(at) || r.stats.scanned != 1 {
				t.Fatalf("timestamp/count: %v %+v", end, r.stats)
			}
			if (r.stats.fallback == 1) != tc.fallback {
				t.Fatalf("fallback=%d", r.stats.fallback)
			}
			if legacyAcceptsRadius(tc.data, tc.link) != tc.legacy {
				t.Fatal("bad legacy oracle fixture")
			}
		})
	}
	for _, port := range []uint16{1812, 1813, 1645, 1646} {
		for _, src := range []bool{false, true} {
			p := prefilterUDPPorts(accounting, 40000, port)
			if src {
				p = prefilterUDPPorts(accounting, port, 40000)
			}
			s := &prefilterTestSource{packets: []prefilterTestPacket{{p, prefilterInfo(p, time.Unix(1, 0))}}}
			var end time.Time
			r := newRadiusPacketSource(context.Background(), s, layers.LinkTypeEthernet, &end, compileRadiusBPF)
			if _, _, err := r.ReadPacketData(); err != nil {
				t.Fatalf("port %d src=%v rejected: %v", port, src, err)
			}
		}
	}
}

func TestRadiusPrefilterNeverRejectsLegacyAccounting(t *testing.T) {
	base := prefilterAccounting(t)
	filter, err := compileRadiusBPF()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise truncation at every boundary and deterministic single-byte mutations.
	check := func(data []byte) {
		ip, offset, ok := radiusFilterIPv4(data, layers.LinkTypeEthernet)
		if !ok {
			return
		}
		ci := prefilterInfo(data, time.Unix(1, 0))
		ci.Length -= offset
		ci.CaptureLength = len(ip)
		if !filter.Matches(ci, ip) && legacyAcceptsRadius(data, layers.LinkTypeEthernet) {
			t.Fatal("prefilter rejected legacy accounting")
		}
	}
	for _, packet := range [][]byte{base, prefilterVLAN(base, 0x8100), prefilterVLAN(base, 0x88a8, 0x8100)} {
		for n := 0; n <= len(packet); n++ {
			check(packet[:n])
		}
		for n := 0; n < len(packet); n++ {
			for _, v := range []byte{0, 1, 4, 6, 17, 0x20, 0x45, 0xff} {
				p := append([]byte{}, packet...)
				p[n] = v
				check(p)
			}
		}
	}
}

func TestRadiusPrefilterCancellationErrorsAndFallback(t *testing.T) {
	packet := prefilterUDPPorts(prefilterAccounting(t), 53, 53)
	at := time.Unix(100, 0)
	for _, cancelCase := range []string{"cancel", "timeout"} {
		t.Run(cancelCase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelCase == "timeout" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer stop()
			}
			s := &prefilterTestSource{packets: []prefilterTestPacket{{packet, prefilterInfo(packet, at)}, {packet, prefilterInfo(packet, at)}}, afterRead: cancel}
			var end time.Time
			r := newRadiusPacketSource(ctx, s, layers.LinkTypeEthernet, &end, compileRadiusBPF)
			_, _, err := r.ReadPacketData()
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation lost: %v", err)
			}
			if s.index > 1 {
				t.Fatal("read beyond cancellation")
			}
		})
	}
	t.Run("read error", func(t *testing.T) {
		want := errors.New("broken capture")
		s := &prefilterTestSource{packets: []prefilterTestPacket{{packet, prefilterInfo(packet, at)}}, terminal: want}
		var end time.Time
		r := newRadiusPacketSource(context.Background(), s, layers.LinkTypeEthernet, &end, compileRadiusBPF)
		_, _, err := r.ReadPacketData()
		if !errors.Is(err, want) || !end.Equal(at) {
			t.Fatalf("error/end changed: %v", err)
		}
	})
	t.Run("compile failure", func(t *testing.T) {
		s := &prefilterTestSource{packets: []prefilterTestPacket{{packet, prefilterInfo(packet, at)}}}
		var end time.Time
		r := newRadiusPacketSource(context.Background(), s, layers.LinkTypeEthernet, &end, func() (*pcap.BPF, error) { return nil, errors.New("unavailable") })
		if _, _, err := r.ReadPacketData(); err != nil || r.stats.filterErrorFiles != 1 || r.stats.fallback != 1 {
			t.Fatalf("failed to preserve fallback: %v %+v", err, r.stats)
		}
	})
}

func writePrefilterCapture(t *testing.T, path string, ng bool, packets []prefilterTestPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var write func(gopacket.CaptureInfo, []byte) error
	if ng {
		w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := w.Flush(); err != nil {
				t.Error(err)
			}
		}()
		write = w.WritePacket
	} else {
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		write = w.WritePacket
	}
	for _, p := range packets {
		if err := write(p.info, p.data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRadiusPrefilterFileProcessingPreservesRecordsAndCaptureEnd(t *testing.T) {
	for _, ng := range []bool{false, true} {
		for _, count := range []int{0, 255, 256, 257} {
			base := time.Unix(1000, 0)
			a := prefilterAccounting(t)
			drop := prefilterUDPPorts(a, 53, 53)
			packets := make([]prefilterTestPacket, 0, count+1)
			for i := 0; i < count; i++ {
				data := a
				if i%2 == 1 {
					data = prefilterVLAN(a, 0x88a8, 0x8100)
				}
				packets = append(packets, prefilterTestPacket{data, prefilterInfo(data, base.Add(time.Duration(i)*time.Millisecond))})
			}
			end := base.Add(time.Hour)
			packets = append(packets, prefilterTestPacket{drop, prefilterInfo(drop, end)})
			path := filepath.Join(t.TempDir(), "capture.cap")
			writePrefilterCapture(t, path, ng, packets)
			collector := NewRadiusCollector(4)
			if err := processRadiusFile(context.Background(), path, collector); err != nil {
				t.Fatal(err)
			}
			if len(collector.msgs) != count || !collector.captureEnd.Equal(end) {
				t.Fatalf("ng=%v count=%d: messages=%d end=%v", ng, count, len(collector.msgs), collector.captureEnd)
			}
			if collector.prefilter.scanned != uint64(count+1) || collector.prefilter.rejected != 1 {
				t.Fatalf("unexpected filter counts: %+v", collector.prefilter)
			}
			for i, m := range collector.msgs {
				if m.tsMs != base.Add(time.Duration(i)*time.Millisecond).UnixMilli() || m.sid != "prefilter" || m.imsi != "123456789012345" {
					t.Fatal("accounting record changed")
				}
			}
		}
	}
}
