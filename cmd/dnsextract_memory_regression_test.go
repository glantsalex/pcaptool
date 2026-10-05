package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/output"
)

// Exercise the real execution path and writers, not just the edge merger. The
// fixture exceeds the observation limit within each file and spans more files
// than workers. Expected attribution timestamps deliberately cover both the
// retained earliest observation and the most recent exact DNS bindings.
func TestDNSExtractManyFileArtifactsPreserveAttributionAndWorkerIndependence(t *testing.T) {
	const fileCount = 32
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	readDir := t.TempDir()
	for i := 0; i < fileCount; i++ {
		writeMemoryRegressionPCAP(t, filepath.Join(readDir, fmt.Sprintf("capture-%03d.pcap", i)), base.Add(time.Duration(i)*time.Minute), i == 0, i == fileCount-1)
	}
	last := base.Add((fileCount - 1) * time.Minute)
	wantTopology := []dns.TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "198.51.100.10", DNSName: "tcp.example", DNSSource: "dns+synack", Protocol: "tcp", Port: 80, ObservedAt: last.Add(220 * time.Millisecond)},
		{IssuerIP: "10.0.0.1", DestinationIP: "198.51.100.10", DNSName: "tcp.example", DNSSource: "dns+synack", Protocol: "tcp", Port: 443, ObservedAt: base.Add(200 * time.Millisecond)},
		{IssuerIP: "10.0.0.1", DestinationIP: "198.51.100.20", DNSName: "udp.example", DNSSource: "dns+synack", Protocol: "udp", Port: 3478, ObservedAt: last.Add(350 * time.Millisecond)},
		{IssuerIP: "10.0.0.1", DestinationIP: "198.51.100.30", DNSSource: "mid-session", Protocol: "tcp", Port: 990, ObservedAt: last.Add(450 * time.Millisecond)},
	}
	writers := map[string]func(io.Writer) error{
		"network-topology-matrix.json":         func(w io.Writer) error { return output.WriteNetworkTopologyMatrixJSON(w, wantTopology) },
		"network-topology-matrix.compact.json": func(w io.Writer) error { return output.WriteNetworkTopologyMatrixCompactJSON(w, wantTopology) },
		"network-topology-matrix.txt":          func(w io.Writer) error { return output.WriteNetworkTopologyMatrix(w, wantTopology) },
		"unique-dns-port-proto.csv":            func(w io.Writer) error { return output.WriteUniqueDNSPortProtoCSV(w, wantTopology) },
		"service-endpoints.txt": func(w io.Writer) error {
			return output.WriteServiceEndpointsJSON(w, dns.BuildServiceEndpoints(wantTopology))
		},
	}
	wantBytes := make(map[string][]byte, len(writers))
	for name, write := range writers {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatal(err)
		}
		wantBytes[name] = b.Bytes()
	}

	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	var sequentialArtifacts map[string][]byte
	for _, workers := range []int{1, 3, 6} {
		t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
			runtime.GOMAXPROCS(workers)
			opts := DefaultDNSExtractOptions()
			opts.NetID = "memory-regression"
			opts.ReadDir = readDir
			opts.OutputRoot = t.TempDir()
			opts.Format = "json"
			opts.DisableSNI = true
			opts.EnforcePrivateAsSource = true
			// No fleet/cache/network enrichment/post-hooks: this test remains
			// hermetic and targets the packet-derived analysis and artifact path.
			if err := executeDNSExtract(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			runDir := findSingleRunDir(t, opts.OutputRoot, opts.NetID)
			for name, want := range wantBytes {
				got, err := os.ReadFile(filepath.Join(runDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s changed attribution/order/timestamps:\ngot %s\nwant %s", name, got, want)
				}
			}
			manifest := readRunArtifactsManifest(t, runDir)
			if manifest.PCAPFilesCount != fileCount || manifest.FirstPacketPCAPFile != "capture-000.pcap" || manifest.FirstPacketTSUTC != base.Format(time.RFC3339Nano) || manifest.PCAPDate != "2026-10-01" {
				t.Errorf("incorrect corpus/first-packet metadata: %+v", manifest)
			}
			entries, err := os.ReadDir(runDir)
			if err != nil {
				t.Fatal(err)
			}
			artifacts := make(map[string][]byte)
			for _, entry := range entries {
				// Manifest paths and run-start times are deliberately run-specific;
				// all packet-derived artifacts must match byte-for-byte.
				if entry.Name() == "_run-artifacts.json" {
					continue
				}
				data, err := os.ReadFile(filepath.Join(runDir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				artifacts[entry.Name()] = data
			}
			if workers == 1 {
				sequentialArtifacts = artifacts
			} else if !reflect.DeepEqual(artifacts, sequentialArtifacts) {
				t.Error("packet-derived artifact set/content differs from sequential execution")
			}
		})
	}
}

func writeMemoryRegressionPCAP(t *testing.T, path string, base time.Time, first, last bool) {
	t.Helper()
	const issuer, resolver, tcpDst, udpDst, ftpDst = "10.0.0.1", "192.0.2.53", "198.51.100.10", "198.51.100.20", "198.51.100.30"
	packets := []timestampedPacket{
		{ts: base, data: buildDNSPacket(t, buildDNSQueryPayload(1, "tcp.example"), issuer, resolver, 53000, 53)},
		{ts: base.Add(100 * time.Millisecond), data: buildDNSPacket(t, buildDNSAResponsePayload(1, "tcp.example", tcpDst), resolver, issuer, 53, 53000)},
		{ts: base.Add(200 * time.Millisecond), data: buildTCPPacket(t, issuer, tcpDst, 40000, 443, true, false)},
		{ts: base.Add(210 * time.Millisecond), data: buildTCPPacket(t, tcpDst, issuer, 443, 40000, true, true)},
		{ts: base.Add(220 * time.Millisecond), data: buildTCPPacket(t, issuer, tcpDst, 40001, 80, true, false)},
		{ts: base.Add(230 * time.Millisecond), data: buildTCPPacket(t, tcpDst, issuer, 80, 40001, true, true)},
		{ts: base.Add(250 * time.Millisecond), data: buildDNSPacket(t, buildDNSQueryPayload(2, "udp.example"), issuer, resolver, 53001, 53)},
		{ts: base.Add(260 * time.Millisecond), data: buildDNSPacket(t, buildDNSAResponsePayload(2, "udp.example", udpDst), resolver, issuer, 53, 53001)},
	}
	for i := 0; i < 130; i++ {
		packets = append(packets, timestampedPacket{ts: base.Add(time.Duration(300+i) * time.Millisecond), data: buildTCPPacket(t, issuer, tcpDst, 40000, 443, false, true)})
	}
	// These observations arrive after later TCP timestamps to cover capture
	// reordering as well as exact first-packet tracking.
	packets = append(packets,
		timestampedPacket{ts: base.Add(350 * time.Millisecond), data: buildUDPPacket(t, issuer, udpDst, 40002, 3478)},
		timestampedPacket{ts: base.Add(360 * time.Millisecond), data: buildUDPPacket(t, udpDst, issuer, 3478, 40002)},
		timestampedPacket{ts: base.Add(400 * time.Millisecond), data: buildUDPPacket(t, issuer, "198.51.100.40", 40003, 123)},
		timestampedPacket{ts: base.Add(410 * time.Millisecond), data: buildUDPPacket(t, "198.51.100.40", issuer, 123, 40003)},
	)
	if first {
		packets = append(packets,
			timestampedPacket{ts: base.Add(450 * time.Millisecond), data: buildTCPPacket(t, issuer, ftpDst, 40004, 40000, true, false)},
			timestampedPacket{ts: base.Add(460 * time.Millisecond), data: buildTCPPacket(t, ftpDst, issuer, 40000, 40004, true, true)},
		)
	}
	if last {
		packets = append(packets,
			timestampedPacket{ts: base.Add(450 * time.Millisecond), data: buildTCPPacket(t, issuer, ftpDst, 40005, 990, true, false)},
			timestampedPacket{ts: base.Add(460 * time.Millisecond), data: buildTCPPacket(t, ftpDst, issuer, 990, 40005, true, true)},
		)
	}
	writePacketsToPCAP(t, path, packets)
}
