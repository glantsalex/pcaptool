package syntrail

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"net/netip"
	"testing"
	"time"
)

func syntheticSyslog(t *testing.T, src string) testPacket {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP("10.4.100.58").To4()}
	udp := &layers.UDP{SrcPort: 50000, DstPort: 6514}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return testPacket{ts: time.Unix(10, 0), data: serializePacket(ethernetLayer(layers.EthernetTypeIPv4), ip, udp, gopacket.Payload([]byte("<140>1 2026-10-10T00:00:00Z host app - - - message")))}
}
func TestSyslogScanQualifiesEarlierSendersAcrossFiles(t *testing.T) {
	first := writePCAP(t, []testPacket{udp4Packet(time.Unix(1, 0), "10.1.1.1", "10.4.100.58", 6514)})
	second := writePCAP(t, []testPacket{syntheticSyslog(t, "10.1.1.2")})
	for _, workers := range []int{1, 4} {
		records, err := ScanFilesWithOptions(context.Background(), []string{first, second}, ScanOptions{Workers: workers, SyslogEligible: func(src, dst netip.Addr) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 {
			t.Fatal(records)
		}
		for _, r := range records {
			if !r.SyslogQualified {
				t.Fatalf("earlier sender missing: %+v", r)
			}
		}
		doc := buildPrivateNonFleetEndpointsDocument(records, nil)
		b := doc.Endpoints[0].Server.Listeners[0]
		if b.FleetDevicesCount != 2 || b.Evidence != "syslog" {
			t.Fatal(b)
		}
	}
	// The same payload from an ineligible sender cannot qualify an endpoint.
	records, err := ScanFilesWithOptions(context.Background(), []string{second}, ScanOptions{SyslogEligible: func(src, dst netip.Addr) bool { return false }})
	if err != nil || len(records) != 1 || records[0].SyslogQualified {
		t.Fatalf("ineligible: %v %v", records, err)
	}
	// Trusted prior evidence avoids requiring today's payload to contain a header.
	cache := NewSyslogCache()
	cache.Add(netip.MustParseAddr("10.4.100.58"), 6514)
	records, err = ScanFilesWithOptions(context.Background(), []string{first}, ScanOptions{SyslogCache: cache})
	if err != nil || len(records) != 1 || !records[0].SyslogQualified {
		t.Fatalf("seed: %v %v", records, err)
	}
}
