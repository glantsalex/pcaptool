package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	capture "github.com/aglants/pcaptool/internal/pcap"
	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Exercise the scanner and all sidecar writers together. The expected raw
// evidence is constructed from the fixture, independently of production
// scanning/merging, and the legacy artifact selectors are frozen below.
func TestFleetSidecarManyFileArtifactsMatchLegacy(t *testing.T) {
	dir := t.TempDir()
	files, wantRecords := writeFleetMemoryFixture(t, dir, 32, 12)
	fleet, err := syntrail.ParseFleetIPv4List(strings.NewReader("10.0.0.1\n10.0.0.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantBuckets := syntrail.ClassifyRecords(wantRecords, fleet)
	originalBuckets := make(syntrail.BucketedRecords, len(wantBuckets))
	for bucket, records := range wantBuckets {
		originalBuckets[bucket] = append([]syntrail.Record(nil), records...)
	}
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug_%t", debug), func(t *testing.T) {
			opt := fleetMemoryArtifactOptions(debug)
			want := legacyFleetArtifactBytes(t, wantBuckets, opt, "fleet-memory")
			for _, workers := range []int{1, 3, 8} {
				t.Run(fmt.Sprintf("workers_%d", workers), func(t *testing.T) {
					opt.ScanOptions = syntrail.ScanOptions{Workers: workers, PacketAdmission: capture.IPv4EndpointAdmission(fleet.Contains)}
					records, err := syntrail.ScanFilesWithOptions(context.Background(), files, opt.ScanOptions)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(records, wantRecords) {
						t.Fatal("scan changed TCP occurrences/order or UDP first-appearance/earliest evidence")
					}
					om := newSYNTrailTestOutputManagerForNet(t, "fleet-memory")
					artifacts, err := runSYNTrailSidecar(context.Background(), om, files, &fleet, opt)
					if err != nil {
						t.Fatal(err)
					}
					entries, err := os.ReadDir(om.RunDir())
					if err != nil {
						t.Fatal(err)
					}
					if len(artifacts) != len(want) || len(entries) != len(want) {
						t.Fatalf("artifact set changed: manifest keys=%d files=%d want=%d", len(artifacts), len(entries), len(want))
					}
					for name, expected := range want {
						data, err := os.ReadFile(om.Path(name))
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(data, expected) {
							t.Errorf("%s differs from frozen legacy selector output", name)
						}
					}
				})
			}
			// The writer selectors may borrow input only when downstream code
			// does not mutate it; in-place trail sorting must receive a copy.
			om := newSYNTrailTestOutputManagerForNet(t, "fleet-memory")
			if _, err := writeSYNTrailArtifacts(om, wantBuckets, opt); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(wantBuckets, originalBuckets) {
				t.Fatal("artifact preparation mutated borrowed bucket evidence")
			}
		})
	}
}

func TestDNSExtractSharedFleetScanArtifactsMatchExplicitLegacyScan(t *testing.T) {
	readDir := t.TempDir()
	writeFleetMemoryFixture(t, readDir, 4, 3)
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n10.0.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	originalScanner := scanSYNTrailFilesWithOptions
	t.Cleanup(func() { scanSYNTrailFilesWithOptions = originalScanner })
	legacyScanCalls := 0
	scanSYNTrailFilesWithOptions = func(ctx context.Context, files []string, opt syntrail.ScanOptions) ([]syntrail.Record, error) {
		legacyScanCalls++
		return originalScanner(ctx, files, opt)
	}

	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug_%t", debug), func(t *testing.T) {
			run := func(workers int) (map[string][]byte, int) {
				beforeCalls := legacyScanCalls
				outputRoot := t.TempDir()
				opts := DefaultDNSExtractOptions()
				opts.ReadDir = readDir
				opts.NetID = "fleet-memory"
				opts.OutputRoot = outputRoot
				opts.Fleet = fleetPath
				opts.FleetScanWorkers = workers
				opts.OnlyTCP = true
				opts.ExcludePorts = "53,123,443,8443"
				opts.EnforcePrivateAsSource = true
				opts.DisableSNI = true
				opts.Debug = debug
				opts.IgnoreNTP = false
				if err := executeDNSExtract(context.Background(), opts); err != nil {
					t.Fatalf("executeDNSExtract(workers=%d): %v", workers, err)
				}

				runDir := findSingleRunDir(t, outputRoot, opts.NetID)
				artifacts := make(map[string][]byte)
				for _, spec := range expectedSYNTrailArtifacts {
					if spec.debugOnly && !debug {
						continue
					}
					contents, err := os.ReadFile(filepath.Join(runDir, spec.filename))
					if err != nil {
						t.Fatalf("read %s: %v", spec.filename, err)
					}
					artifacts[spec.filename] = contents
				}
				return artifacts, legacyScanCalls - beforeCalls
			}

			shared, sharedCalls := run(0)
			if sharedCalls != 0 {
				t.Fatalf("default shared path invoked legacy scanner %d times, want 0", sharedCalls)
			}
			legacy, legacyCalls := run(2)
			if legacyCalls != 1 {
				t.Fatalf("explicit worker path invoked legacy scanner %d times, want 1", legacyCalls)
			}
			if !reflect.DeepEqual(shared, legacy) {
				for name, want := range legacy {
					if !bytes.Equal(shared[name], want) {
						t.Errorf("shared %s differs from explicit legacy scan", name)
					}
				}
			}
		})
	}
}

func TestDNSExtractDefaultFleetScanRecoversMixedInterfacePCAPNGWithOneStrictFileScan(t *testing.T) {
	readDir := t.TempDir()
	path := filepath.Join(readDir, "mixed-interfaces.pcap")
	writeMixedInterfaceFleetPCAPNG(t, path)
	if !canUseSharedFleetScan([]string{path}) {
		t.Fatal("PCAPNG input named .pcap was not admitted to shared fleet scanning")
	}
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fleet, err := syntrail.LoadFleetIPv4File(fleetPath)
	if err != nil {
		t.Fatal(err)
	}
	wantRecords, err := syntrail.ScanFilesWithOptions(context.Background(), []string{path}, syntrail.ScanOptions{
		Workers:         1,
		PacketAdmission: capture.IPv4EndpointAdmission(fleet.Contains),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantArtifacts := legacyFleetArtifactBytes(t, syntrail.ClassifyRecords(wantRecords, fleet), fleetMemoryArtifactOptions(true), "fleet-fallback")

	originalScanner := scanSYNTrailFilesWithOptions
	originalFileScanner := scanSYNTrailFile
	t.Cleanup(func() {
		scanSYNTrailFilesWithOptions = originalScanner
		scanSYNTrailFile = originalFileScanner
	})
	legacyCalls := 0
	scanSYNTrailFilesWithOptions = func(ctx context.Context, files []string, opt syntrail.ScanOptions) ([]syntrail.Record, error) {
		legacyCalls++
		return originalScanner(ctx, files, opt)
	}
	strictFileScans := 0
	scanSYNTrailFile = func(ctx context.Context, path string, admit capture.PacketAdmission) ([]syntrail.Record, error) {
		strictFileScans++
		return originalFileScanner(ctx, path, admit)
	}

	outputRoot := t.TempDir()
	opts := DefaultDNSExtractOptions()
	opts.ReadDir = readDir
	opts.NetID = "fleet-fallback"
	opts.OutputRoot = outputRoot
	opts.Fleet = fleetPath
	opts.FleetScanWorkers = 0
	opts.DisableSNI = true
	opts.Debug = true
	opts.IgnoreNTP = false
	if err := executeDNSExtract(context.Background(), opts); err != nil {
		t.Fatalf("executeDNSExtract() mixed-interface recovery error = %v", err)
	}
	if legacyCalls != 0 {
		t.Fatalf("default shared path invoked full legacy scanner %d times, want 0", legacyCalls)
	}
	if strictFileScans != 1 {
		t.Fatalf("strict compatibility file scans = %d, want 1", strictFileScans)
	}
	runDir := findSingleRunDir(t, outputRoot, opts.NetID)
	for name, want := range wantArtifacts {
		got, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("recovered %s differs from strict legacy fleet scan", name)
		}
	}
	trail, err := os.ReadFile(filepath.Join(runDir, "fleet-to-public-trail.csv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"10.0.0.1,203.0.113.10,443,tcp",
		"10.0.0.1,203.0.113.11,8443,tcp",
	} {
		if !strings.Contains(string(trail), want) {
			t.Fatalf("recovered fleet trail omitted compatible-interface evidence %q:\n%s", want, trail)
		}
	}
	manifest := readRunArtifactsManifest(t, runDir)
	matrix := mustReadTestFile(t, manifest.Files["network_topology_matrix_json"])
	for _, want := range []string{"203.0.113.10", "203.0.113.11"} {
		if !strings.Contains(matrix, want) {
			t.Fatalf("connection correlation did not continue to compatible endpoint %s after read error:\n%s", want, matrix)
		}
	}
}

func TestDNSExtractMixedInterfaceStrictFileRecoveryFailureReturnsBeforeOutput(t *testing.T) {
	readDir := t.TempDir()
	writeMixedInterfaceFleetPCAPNG(t, filepath.Join(readDir, "mixed-interfaces.pcap"))
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	originalFileScanner := scanSYNTrailFile
	originalScanner := scanSYNTrailFilesWithOptions
	t.Cleanup(func() {
		scanSYNTrailFile = originalFileScanner
		scanSYNTrailFilesWithOptions = originalScanner
	})
	wantErr := errors.New("strict fleet reread failed")
	scanSYNTrailFile = func(context.Context, string, capture.PacketAdmission) ([]syntrail.Record, error) {
		return nil, wantErr
	}
	scanSYNTrailFilesWithOptions = func(context.Context, []string, syntrail.ScanOptions) ([]syntrail.Record, error) {
		t.Fatal("full legacy scanner called from shared recovery")
		return nil, nil
	}

	outputRoot := t.TempDir()
	opts := DefaultDNSExtractOptions()
	opts.ReadDir = readDir
	opts.NetID = "fleet-recovery-error"
	opts.OutputRoot = outputRoot
	opts.Fleet = fleetPath
	opts.FleetScanWorkers = 0
	opts.DisableSNI = true
	opts.IgnoreNTP = false
	err := executeDNSExtract(context.Background(), opts)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "validate fleet evidence after connection read error") {
		t.Fatalf("executeDNSExtract() error = %v, want contextual %v", err, wantErr)
	}
	entries, readErr := os.ReadDir(outputRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("strict recovery failure wrote output entries: %v", entries)
	}
}

func writeMixedInterfaceFleetPCAPNG(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	rawInterface, err := w.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeRaw, SnapLength: 65535})
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	packets := []struct {
		ts             time.Time
		data           []byte
		interfaceIndex int
	}{
		{ts: base, data: buildTCPPacket(t, "10.0.0.1", "203.0.113.10", 41000, 443, true, false)},
		{ts: base.Add(time.Millisecond), data: buildTCPPacket(t, "203.0.113.10", "10.0.0.1", 443, 41000, true, true)},
		{ts: base.Add(time.Second), data: []byte{0x45, 0, 0, 20}, interfaceIndex: rawInterface},
		{ts: base.Add(2 * time.Second), data: buildTCPPacket(t, "10.0.0.1", "203.0.113.11", 41000, 8443, true, false)},
		{ts: base.Add(2*time.Second + time.Millisecond), data: buildTCPPacket(t, "203.0.113.11", "10.0.0.1", 8443, 41000, true, true)},
	}
	for _, packet := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp: packet.ts, CaptureLength: len(packet.data), Length: len(packet.data), InterfaceIndex: packet.interfaceIndex,
		}
		if err := w.WritePacket(ci, packet.data); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func fleetMemoryArtifactOptions(debug bool) synTrailArtifactOptions {
	return synTrailArtifactOptions{
		Debug: debug, FTPControlPorts: map[uint16]struct{}{21: {}, 990: {}},
		FTPPassiveMinPort: 30000, ServerSummaryExcludeUDPPorts: map[uint16]struct{}{33434: {}},
	}
}

// Each file deliberately contains repeated TCP occurrences, interleaved UDP,
// rejected non-fleet traffic, and SYN+ACK packets. Later files have earlier
// timestamps. FTP control evidence appears only in the final file.
func writeFleetMemoryFixture(t *testing.T, dir string, fileCount, repetitions int) ([]string, []syntrail.Record) {
	t.Helper()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var files []string
	var tcp []syntrail.Record
	type udpKey struct {
		src, dst netip.Addr
		port     uint16
	}
	udp := make(map[udpKey]syntrail.Record)
	var order []udpKey
	for fileIndex := 0; fileIndex < fileCount; fileIndex++ {
		ts := base.Add(time.Duration(fileCount-fileIndex) * time.Minute)
		src := fmt.Sprintf("10.0.0.%d", 1+fileIndex%2)
		peer := fmt.Sprintf("10.0.0.%d", 2-fileIndex%2)
		var packets []timestampedPacket
		addTCP := func(from, to string, port uint16, timestamp time.Time) {
			packets = append(packets, timestampedPacket{ts: timestamp, data: buildTCPPacket(t, from, to, 41000, port, true, false)})
			tcp = append(tcp, syntrail.Record{SrcIP: netip.MustParseAddr(from), DstIP: netip.MustParseAddr(to), DstPort: port, Protocol: syntrail.ProtocolTCP, Timestamp: timestamp})
		}
		addUDP := func(from, to string, port uint16, timestamp time.Time) {
			packets = append(packets, timestampedPacket{ts: timestamp, data: buildUDPPacket(t, from, to, 41000, port)})
			key := udpKey{netip.MustParseAddr(from), netip.MustParseAddr(to), port}
			r := syntrail.Record{SrcIP: key.src, DstIP: key.dst, DstPort: port, Protocol: syntrail.ProtocolUDP, Timestamp: timestamp}
			old, exists := udp[key]
			if !exists {
				order = append(order, key)
			}
			if !exists || timestamp.Before(old.Timestamp) {
				udp[key] = r
			}
		}
		for i := 0; i < repetitions; i++ {
			at := ts.Add(time.Duration(i%5) * time.Millisecond)
			addTCP(src, "203.0.113.10", 443, at)
			addTCP(src, "192.168.1.20", 8443, at)
			addTCP(src, peer, 9443, at)
			addTCP("192.168.1.30", src, 22, at)
			addUDP(src, "203.0.113.10", 3478, at)
			addUDP(src, "192.168.1.20", 33434, at)
			addUDP(src, "192.168.1.20", 5353, at)
			addUDP("192.168.1.30", src, 53, at)
		}
		addTCP(src, "203.0.113.20", 40000, ts)
		addTCP(src, "192.168.1.40", 40000, ts)
		if fileIndex == fileCount-1 {
			for _, device := range []string{"10.0.0.1", "10.0.0.2"} {
				addTCP(device, "203.0.113.20", 990, ts)
				addTCP(device, "192.168.1.40", 990, ts)
			}
		}
		packets = append(packets,
			timestampedPacket{ts: ts, data: buildTCPPacket(t, "10.9.9.9", "203.0.113.10", 41000, 443, true, false)},
			timestampedPacket{ts: ts, data: buildTCPPacket(t, "203.0.113.10", src, 443, 41000, true, true)},
		)
		path := filepath.Join(dir, fmt.Sprintf("capture-%04d.pcap", fileIndex))
		writePacketsToPCAP(t, path, packets)
		files = append(files, path)
	}
	for _, key := range order {
		tcp = append(tcp, udp[key])
	}
	return files, tcp
}

// Freeze pre-change artifact selection independently of the production
// selectors. Output writers themselves are unchanged by this optimization.
func legacyFleetArtifactBytes(t *testing.T, buckets syntrail.BucketedRecords, opt synTrailArtifactOptions, netID string) map[string][]byte {
	t.Helper()
	clone := func(bucket syntrail.Bucket) []syntrail.Record {
		return append([]syntrail.Record(nil), buckets[bucket]...)
	}
	public, private := syntrail.SplitFleetToNonFleetByDestinationLocality(clone(syntrail.BucketFleetToNonFleet))
	tcpOnly := func(records []syntrail.Record) []syntrail.Record {
		out := make([]syntrail.Record, 0, len(records))
		for _, r := range records {
			if r.Protocol == "" || r.Protocol == syntrail.ProtocolTCP {
				out = append(out, r)
			}
		}
		return out
	}
	summary := func(records []syntrail.Record) []syntrail.Record {
		type pair struct{ src, dst netip.Addr }
		controls := make(map[pair]bool)
		for _, r := range records {
			if r.Protocol == "" || r.Protocol == syntrail.ProtocolTCP {
				if _, ok := opt.FTPControlPorts[r.DstPort]; ok {
					controls[pair{r.SrcIP, r.DstIP}] = true
				}
			}
		}
		var out []syntrail.Record
		for _, r := range records {
			_, control := opt.FTPControlPorts[r.DstPort]
			if (r.Protocol == "" || r.Protocol == syntrail.ProtocolTCP) && r.DstPort >= opt.FTPPassiveMinPort && !control && controls[pair{r.SrcIP, r.DstIP}] {
				continue
			}
			if r.Protocol == syntrail.ProtocolUDP {
				if _, excluded := opt.ServerSummaryExcludeUDPPorts[r.DstPort]; excluded {
					continue
				}
			}
			out = append(out, r)
		}
		return out
	}
	files := make(map[string][]byte)
	write := func(name string, fn func(io.Writer) error) {
		var b bytes.Buffer
		if err := fn(&b); err != nil {
			t.Fatal(err)
		}
		files[name] = b.Bytes()
	}
	publicSummary, privateSummary := summary(public), summary(private)
	probes := tcpOnly(clone(syntrail.BucketPrivateNonFleetToFleet))
	write("public-servers-unique.csv", func(w io.Writer) error { return syntrail.WritePublicServersCSV(w, publicSummary) })
	write(privateNonFleetEndpointsFilename, func(w io.Writer) error { return syntrail.WritePrivateNonFleetEndpointsJSON(w, privateSummary, probes) })
	write(flowDirectionCorrectionSQLFilename, func(w io.Writer) error {
		return writeFlowDirectionCorrectionSQLContent(w, netID, syntrail.PrivateServerTuples(privateSummary))
	})
	if opt.Debug {
		write("fleet-to-public-trail.csv", func(w io.Writer) error { return syntrail.WriteProtocolTrailCSV(w, public) })
		write("fleet-to-private-nonfleet-trail.csv", func(w io.Writer) error { return syntrail.WriteProtocolTrailCSV(w, private) })
		write("fleet-to-public-unique.csv", func(w io.Writer) error { return syntrail.WriteProtocolUniqueCSV(w, public) })
		write("fleet-to-private-nonfleet-syn-unique.csv", func(w io.Writer) error { return syntrail.WriteTCPUniqueCSV(w, tcpOnly(private)) })
		write("fleet-to-fleet-tcp-syn-trail.csv", func(w io.Writer) error { return syntrail.WriteTrailCSV(w, tcpOnly(clone(syntrail.BucketFleetToFleet))) })
		write("fleet-to-fleet-tcp-syn-unique.csv", func(w io.Writer) error {
			return syntrail.WriteUniqueCSV(w, tcpOnly(clone(syntrail.BucketFleetToFleet)))
		})
		write("private-nonfleet-to-fleet-trail.csv", func(w io.Writer) error {
			return syntrail.WriteProtocolTrailCSV(w, clone(syntrail.BucketPrivateNonFleetToFleet))
		})
		write("private-nonfleet-to-fleet-tcp-syn-unique.csv", func(w io.Writer) error { return syntrail.WriteUniqueCSV(w, probes) })
	}
	return files
}
