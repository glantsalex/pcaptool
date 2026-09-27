package pcap

import (
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketAdmission reports whether a decoded packet may contribute to a scan.
// A nil admission predicate means that all packets are admitted.
type PacketAdmission func(gopacket.Packet) bool

// IPv4EndpointAdmission returns a predicate that admits only IPv4 packets for
// which contains reports either the source or destination address as a member.
// A nil membership function admits no packets.
func IPv4EndpointAdmission(contains func(netip.Addr) bool) PacketAdmission {
	return func(packet gopacket.Packet) bool {
		if contains == nil || packet == nil {
			return false
		}
		layer := packet.Layer(layers.LayerTypeIPv4)
		ip, ok := layer.(*layers.IPv4)
		if !ok || len(ip.SrcIP) != 4 || len(ip.DstIP) != 4 {
			return false
		}
		src := netip.AddrFrom4([4]byte{ip.SrcIP[0], ip.SrcIP[1], ip.SrcIP[2], ip.SrcIP[3]})
		if contains(src) {
			return true
		}
		dst := netip.AddrFrom4([4]byte{ip.DstIP[0], ip.DstIP[1], ip.DstIP[2], ip.DstIP[3]})
		return contains(dst)
	}
}
