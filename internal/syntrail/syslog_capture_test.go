package syntrail

import (
	"context"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/google/gopacket/layers"
)

// The operational sample is deliberately not checked in: packet payloads may
// contain customer data. Set PCAP_SYSLOG_SAMPLE to run the supplied capture.
func TestOperationalSyslogSample(t *testing.T) {
	path := os.Getenv("PCAP_SYSLOG_SAMPLE")
	if path == "" {
		t.Skip("set PCAP_SYSLOG_SAMPLE for operational sample")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	source, err := packetSource(f)
	if err != nil {
		t.Fatal(err)
	}
	count, truncated := 0, 0
	endpoints := map[syslogEndpoint]bool{}
	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			t.Fatal("non-UDP")
		}
		if !RecognizeSyslog(udp.Payload) {
			t.Fatalf("packet %d header not recognized", count+1)
		}
		r, ok := udpRecord(packet)
		if !ok {
			t.Fatal("UDP record rejected")
		}
		endpoints[syslogEndpoint{r.DstIP, r.DstPort}] = true
		count++
		if packet.Metadata().CaptureLength < packet.Metadata().Length {
			truncated++
		}
	}
	if count != 24 || truncated != 3 || len(endpoints) != 2 {
		t.Fatalf("packets=%d truncated=%d endpoints=%d", count, truncated, len(endpoints))
	}
	for _, workers := range []int{1, 4} {
		records, err := ScanFilesWithOptions(context.Background(), []string{path, path}, ScanOptions{Workers: workers, SyslogEligible: func(src, dst netip.Addr) bool {
			return !endpoints[syslogEndpoint{src, 6514}] && endpoints[syslogEndpoint{dst, 6514}]
		}})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			if !r.SyslogQualified {
				t.Fatalf("qualification lost: %+v", r)
			}
		}
	}
}
func BenchmarkSyslogSampleScan(b *testing.B) {
	path := os.Getenv("PCAP_SYSLOG_SAMPLE")
	if path == "" {
		b.Skip("set PCAP_SYSLOG_SAMPLE")
	}
	for _, mode := range []string{"baseline", "recognize", "seeded"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				cache := NewSyslogCache()
				if mode == "seeded" {
					cache.Add(netip.MustParseAddr("10.4.100.58"), 6514)
					cache.Add(netip.MustParseAddr("10.4.101.202"), 6514)
				}
				var eligible func(netip.Addr, netip.Addr) bool
				if mode != "baseline" {
					eligible = func(_, _ netip.Addr) bool { return true }
				}
				if _, err := scanFileWithSyslog(context.Background(), path, nil, cache, eligible); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
