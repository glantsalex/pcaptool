package dns

import (
	"encoding/binary"
	"net"
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

func TestExtractDNSResponseFromRaw_UDPTruncatedSalvagesCompleteARecord(t *testing.T) {
	full := buildRawDNSResponseA(
		"api.store.ccv.eu",
		[]string{"80.72.142.122", "80.72.142.123"},
		true,
	)
	// Keep the first complete answer and only the start of the second one.
	truncated := full[:len(full)-2]

	id, name, answers, ok := extractDNSResponseFromRaw(truncated, L4ProtoUDP, true)
	if !ok {
		t.Fatalf("expected response salvage success")
	}
	if id != 0x090a {
		t.Fatalf("expected DNS ID 0x090a, got 0x%x", id)
	}
	if name != "api.store.ccv.eu" {
		t.Fatalf("expected qname api.store.ccv.eu, got %q", name)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 salvaged answer, got %d", len(answers))
	}
	if got := answers[0].String(); got != "80.72.142.122" {
		t.Fatalf("expected first answer 80.72.142.122, got %s", got)
	}
}

func TestExtractDNSResponseFromRaw_RejectsQueryPayload(t *testing.T) {
	raw := buildRawDNSQuery("example.com", uint16(layers.DNSTypeA))
	if _, _, _, ok := extractDNSResponseFromRaw(raw, L4ProtoUDP, true); ok {
		t.Fatalf("expected query payload to be rejected as response")
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

func buildRawDNSResponseA(name string, ips []string, compressAnswerName bool) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x090a)           // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)           // standard response, no error
	binary.BigEndian.PutUint16(msg[4:6], 1)                // QDCOUNT
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(ips))) // ANCOUNT
	binary.BigEndian.PutUint16(msg[8:10], 0)               // NSCOUNT
	binary.BigEndian.PutUint16(msg[10:12], 0)              // ARCOUNT

	for _, lbl := range strings.Split(name, ".") {
		msg = append(msg, byte(len(lbl)))
		msg = append(msg, []byte(lbl)...)
	}
	msg = append(msg, 0x00) // end of QNAME

	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(layers.DNSTypeA))
	msg = append(msg, tmp...)
	binary.BigEndian.PutUint16(tmp, 1) // QCLASS IN
	msg = append(msg, tmp...)

	for _, ipStr := range ips {
		if compressAnswerName {
			msg = append(msg, 0xc0, 0x0c)
		} else {
			for _, lbl := range strings.Split(name, ".") {
				msg = append(msg, byte(len(lbl)))
				msg = append(msg, []byte(lbl)...)
			}
			msg = append(msg, 0x00)
		}

		binary.BigEndian.PutUint16(tmp, uint16(layers.DNSTypeA))
		msg = append(msg, tmp...)
		binary.BigEndian.PutUint16(tmp, 1) // CLASS IN
		msg = append(msg, tmp...)

		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 3)
		msg = append(msg, ttl...)

		binary.BigEndian.PutUint16(tmp, 4)
		msg = append(msg, tmp...)

		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			panic("invalid IPv4 test address: " + ipStr)
		}
		msg = append(msg, ip[0], ip[1], ip[2], ip[3])
	}

	return msg
}
