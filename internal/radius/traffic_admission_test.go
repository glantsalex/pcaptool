package radius

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func admissionPacket(t testing.TB, port layers.UDPPort, response, vlan bool, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 181, 0, 1), DstIP: net.IPv4(10, 250, 0, 99)}
	udp := &layers.UDP{SrcPort: 35000, DstPort: port}
	if response {
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
		udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	parts := []gopacket.SerializableLayer{eth}
	if vlan {
		eth.EthernetType = layers.EthernetTypeDot1Q
		parts = append(parts, &layers.Dot1Q{VLANIdentifier: 2511, Type: layers.EthernetTypeIPv4})
	}
	parts = append(parts, ip, udp, gopacket.Payload(payload))
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, parts...); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func accountingPayload(code byte) []byte {
	data := make([]byte, 26)
	data[0], data[20], data[21], data[25] = code, 40, 6, 1
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

func TestExcludeRADIUSBeforeMembership(t *testing.T) {
	for _, port := range []layers.UDPPort{1812, 1813, 1645, 1646} {
		for _, code := range []byte{1, 2, 3, 4, 5, 11, 12, 13} {
			for _, response := range []bool{false, true} {
				for _, vlan := range []bool{false, true} {
					t.Run(fmt.Sprintf("port-%d/code-%d/response-%t/vlan-%t", port, code, response, vlan), func(t *testing.T) {
						packet := admissionPacket(t, port, response, vlan, accountingPayload(code))
						admit := ExcludePackets(func(gopacket.Packet) bool { t.Fatal("membership consulted for RADIUS"); return true })
						if admit(packet) || ExcludePackets(nil)(packet) {
							t.Fatal("RADIUS admitted as traffic")
						}
					})
				}
			}
		}
	}
}

func TestExcludeRADIUSPreservesOrdinaryNASPolicy(t *testing.T) {
	badCode := accountingPayload(0)
	badLength := accountingPayload(4)
	badLength[3]++
	badAttribute := accountingPayload(4)
	badAttribute[21] = 1
	for _, tc := range []struct {
		name string
		port layers.UDPPort
		data []byte
	}{
		{"ordinary NAS traffic", 514, []byte("<34>Oct 11 22:14:15 host app: data")},
		{"other UDP on RADIUS port", 1813, []byte("ordinary traffic")},
		{"unknown code", 1813, badCode},
		{"truncated message", 1813, badLength},
		{"malformed attribute", 1813, badAttribute},
		{"unrecognized port", 9999, accountingPayload(4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := admissionPacket(t, tc.port, false, true, tc.data)
			for _, member := range []bool{false, true} {
				calls := 0
				admit := ExcludePackets(func(gopacket.Packet) bool { calls++; return member })
				if got := admit(packet); got != member || calls != 1 {
					t.Fatalf("admitted=%t membership=%t calls=%d", got, member, calls)
				}
			}
			if !ExcludePackets(nil)(packet) {
				t.Fatal("non-RADIUS rejected without membership policy")
			}
		})
	}
	if ExcludePackets(nil)(nil) {
		t.Fatal("nil packet admitted")
	}
}

func TestExcludeRADIUSAllowsPadding(t *testing.T) {
	packet := admissionPacket(t, 1813, true, true, append(accountingPayload(5), 0, 0))
	if ExcludePackets(nil)(packet) {
		t.Fatal("padded RADIUS response admitted")
	}
}

func BenchmarkExcludeRADIUS(b *testing.B) {
	packet := admissionPacket(b, 1813, false, true, accountingPayload(4))
	admit := ExcludePackets(func(gopacket.Packet) bool { return true })
	b.ReportAllocs()
	for b.Loop() {
		if admit(packet) {
			b.Fatal("RADIUS admitted")
		}
	}
}
