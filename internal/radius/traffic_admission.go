package radius

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ExcludePackets rejects recognized RADIUS control packets before invoking the
// later traffic admission policy. Use only after the unfiltered accounting pass.
// A nil policy admits all non-RADIUS packets. NAS addresses are not blacklisted:
// ordinary traffic from the same address still follows the supplied policy.
func ExcludePackets(admit func(gopacket.Packet) bool) func(gopacket.Packet) bool {
	return func(packet gopacket.Packet) bool {
		if packet == nil || isRADIUSPacket(packet) {
			return false
		}
		return admit == nil || admit(packet)
	}
}

func isRADIUSPacket(packet gopacket.Packet) bool {
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || !(isRadiusPort(udp.SrcPort) || isRadiusPort(udp.DstPort)) {
		return false
	}
	data := udp.Payload
	if len(data) < 20 || len(data) > 4096 {
		return false
	}
	switch layers.RADIUSCode(data[0]) {
	case layers.RADIUSCodeAccessRequest, layers.RADIUSCodeAccessAccept,
		layers.RADIUSCodeAccessReject, layers.RADIUSCodeAccountingRequest,
		layers.RADIUSCodeAccountingResponse, layers.RADIUSCodeAccessChallenge,
		layers.RADIUSCodeStatusServer, layers.RADIUSCodeStatusClient:
	default:
		return false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 20 || length > len(data) {
		return false
	}
	// Validate the same header/attribute lengths as the accounting decoder,
	// without allocating copies of every attribute in subsequent packet scans.
	// Trailing UDP padding is outside the RADIUS message and may be ignored.
	for offset := 20; offset < length; {
		if length-offset < 2 {
			return false
		}
		size := int(data[offset+1])
		if size < 2 || size > length-offset {
			return false
		}
		offset += size
	}
	return true
}
