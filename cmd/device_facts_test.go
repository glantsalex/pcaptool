package cmd

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
)

// Exercise the actual Ethernet/file decoders, both passes and the ordered
// worker merge. The timed resolver models address rotation and reassignment.
func TestDeviceFactsAcrossCaptureAndLeaseBoundaries(t *testing.T) {
	hostnames := dns.NewHostnames()

	base := time.Unix(1700000000, 0).UTC()
	const first, second, unknown = "10.0.0.1", "10.0.0.2", "10.0.0.9"
	const server, other = "203.0.113.10", "203.0.113.11"
	resolve := func(ip netip.Addr, ts time.Time) string {
		switch ip.String() {
		case first:
			if ts.Before(base.Add(10 * time.Second)) {
				return "A"
			}
			if ts.Before(base.Add(11 * time.Second)) {
				return ""
			}
			return "B"
		case second:
			return "A"
		}
		return ""
	}
	hello := func(sec int, dev, dst string, port uint16, name string) timestampedPacket {
		return timestampedPacket{base.Add(time.Duration(sec) * time.Second), buildTCPPacketWithPayload(t, dev, dst, 50001, port, false, true, buildTLSClientHelloPayload(name))}
	}
	wireDNS := func(sec int, dev, name, dst string) timestampedPacket {
		msg := buildDNSAResponsePayload(uint16(sec), name, dst)
		payload := make([]byte, 2, len(msg)+2)
		binary.BigEndian.PutUint16(payload, uint16(len(msg)))
		payload = append(payload, msg...)
		return timestampedPacket{base.Add(time.Duration(sec) * time.Second), buildTCPPacketWithPayload(t, "192.0.2.53", dev, 53, 55000, false, true, payload)}
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "late.pcap"), filepath.Join(dir, "early.pcap")
	writePacketsToPCAP(t, a, []timestampedPacket{
		hello(5, second, server, 8443, "a.example"), hello(6, first, server, 8443, "B.example."),
		hello(7, second, other, 8443, "b.example"), hello(7, first, server, 9443, "b.example"),
		hello(10, first, server, 8443, "ambiguous.example"), hello(12, first, server, 8443, "new-owner.example"),
		{base.Add(12 * time.Second), buildTCPPacket(t, server, first, 999, 40000, false, true)},
		{base.Add(7 * time.Second), buildUDPPacket(t, second, server, 50000, 900)},
		{base.Add(8 * time.Second), buildUDPPacket(t, server, second, 900, 50000)},
		{base.Add(8 * time.Second), buildTCPPacket(t, second, other, 45000, 8080, false, true)},
	})
	early := []timestampedPacket{
		// The other file binds the DNS query to UDP/900. This mid-session TCP contact remains unnamed.
		{base.Add(7 * time.Second), buildTCPPacket(t, server, second, 900, 40000, false, true)},
		wireDNS(2, first, "dns.example", server), wireDNS(3, first, "dns.example", server),
		wireDNS(1, unknown, "unmapped.example", other), wireDNS(4, first, "unused.example", "203.0.113.90"),
		hello(2, first, server, 8443, "A.EXAMPLE"), hello(2, unknown, server, 8443, "unmapped.example"),
		hello(3, first, server, 123, "excluded.example"),
	}
	for i := 0; i < 1000; i++ {
		early = append(early, hello(3, first, server, 8443, "a.example"))
	}
	writePacketsToPCAP(t, b, early)
	type key struct {
		id, dst, name, proto string
		port                 uint16
	}
	want := map[key]bool{
		{"A", server, "a.example", "tcp", 8443}: true, {"A", server, "b.example", "tcp", 8443}: true, {"A", other, "b.example", "tcp", 8443}: true,
		{"A", server, "b.example", "tcp", 9443}: true, {"B", server, "new-owner.example", "tcp", 8443}: true,
		{"B", server, "", "tcp", 999}: true, {"A", server, "", "tcp", 900}: true, {"A", server, "dns.example", "udp", 900}: true, {"A", other, "", "tcp", 8080}: true,
	}
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	var reference []dns.TopologyEntry
	for _, mode := range []struct {
		workers int
		files   []string
	}{{1, []string{a, b}}, {4, []string{b, a, b, a}}} {
		runtime.GOMAXPROCS(mode.workers)
		facts := dns.NewFactCollection(hostnames, resolve, true, time.Minute)
		opt := dns.PacketScanOptions{Facts: facts, IssuerIdentity: func(ip string, ts time.Time) string { return resolve(netip.MustParseAddr(ip), ts) }}
		txs, _, _, err := dns.CollectDNS(context.Background(), hostnames, mode.files, nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		if len(txs) != 3 {
			t.Fatalf("DNS transactions=%d, want 3 TCP responses", len(txs))
		}
		facts.Prepare(txs, nil, false)
		_, _, err = dns.AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(context.Background(), hostnames, mode.files, txs, false, false, map[uint16]struct{}{123: {}}, true, nil, nil, 0, opt)
		if err != nil {
			t.Fatal(err)
		}
		if facts.Len() != len(want) {
			t.Errorf("retained %d facts, want %d", facts.Len(), len(want))
		}
		rows := facts.Take(30000, nil)
		got := map[key]bool{}
		for _, r := range rows {
			got[key{r.IssuerIP, r.DestinationIP, r.DNSName, r.Protocol, r.Port}] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("facts = %+v, want %+v", got, want)
		}
		if reference != nil && !reflect.DeepEqual(rows, reference) {
			t.Fatalf("file order or overlap changed rows")
		}
		reference = rows
	}
}
