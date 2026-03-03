package dns

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestExtractDNSQueryNameFromRaw_UDPTruncatedSalvage(t *testing.T) {
	full := buildRawDNSQuery("a293ycymj5u8y6-ats.iot.eu-west-1.amazonaws.com", uint16(layers.DNSTypeA))
	// Simulate snaplen truncation in the final label: keep only ".co".
	// Drops: 'm' + root terminator + QTYPE/QCLASS.
	truncated := full[:len(full)-6]

	id, name, ok := extractDNSQueryNameFromRaw(truncated, L4ProtoUDP, true)
	if !ok {
		t.Fatalf("expected salvage success")
	}
	if id != 0x090a {
		t.Fatalf("expected DNS ID 0x090a, got 0x%x", id)
	}
	want := "a293ycymj5u8y6-ats.iot.eu-west-1.amazonaws.co"
	if name != want {
		t.Fatalf("expected %q, got %q", want, name)
	}
}

func TestExtractDNSQueryNameFromRaw_TCPTruncatedSalvage(t *testing.T) {
	full := buildRawDNSQuery("mkt-piot-pro-certificates.auth.eu-west-1.amazoncognito.com", uint16(layers.DNSTypeA))
	// Simulate truncation in the final label.
	truncatedDNS := full[:len(full)-3]

	tcpPayload := make([]byte, 2+len(truncatedDNS))
	binary.BigEndian.PutUint16(tcpPayload[:2], uint16(len(full)))
	copy(tcpPayload[2:], truncatedDNS)

	_, name, ok := extractDNSQueryNameFromRaw(tcpPayload, L4ProtoTCP, true)
	if !ok {
		t.Fatalf("expected TCP salvage success")
	}
	if !strings.HasPrefix(name, "mkt-piot-pro-certificates.auth.eu-west-1.amazoncognito") {
		t.Fatalf("expected salvaged partial prefix, got %q", name)
	}
}

func TestExtractDNSQueryNameFromRaw_RejectsNonAQuery(t *testing.T) {
	raw := buildRawDNSQuery("example.com", uint16(layers.DNSTypeAAAA))
	if _, _, ok := extractDNSQueryNameFromRaw(raw, L4ProtoUDP, true); ok {
		t.Fatalf("expected non-A query to be rejected")
	}
}

func buildRawDNSQuery(name string, qType uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x090a) // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // standard query
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT

	for _, lbl := range strings.Split(name, ".") {
		msg = append(msg, byte(len(lbl)))
		msg = append(msg, []byte(lbl)...)
	}
	msg = append(msg, 0x00) // end of QNAME

	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, qType)
	msg = append(msg, tmp...)
	binary.BigEndian.PutUint16(tmp, 1) // QCLASS IN
	msg = append(msg, tmp...)

	return msg
}
