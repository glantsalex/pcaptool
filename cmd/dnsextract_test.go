package cmd

import (
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

func TestTruncatedDNSPacketsArtifactWrittenAndManifestedOnlyWithDebug(t *testing.T) {
	restoreDNSExtractFlags(t)
	resolveDNSNamesIPv4 = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil
	}

	readDir := t.TempDir()
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))

	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "debug_false", true: "debug_true"}[debug], func(t *testing.T) {
			outputRoot := t.TempDir()
			flagReadDir = readDir
			flagNetID = "net"
			flagOutputRoot = outputRoot
			flagFormat = "table"
			flagFleet = ""
			flagExportCSV = ""
			flagConnectivityShort = false
			flagRadiusIMSI = false
			flagOnlyTCP = false
			flagIgnoreNTP = false
			flagExcludePorts = "53"
			flagFTPControlPorts = "21,990"
			flagFTPPassiveMinPort = "30000"
			flagServerSummaryExcludeUDPPorts = "33434-33534"
			flagDNSIPFile = ""
			flagTopologyDNSWindow = dns.DefaultTopologyBuildOptions().MaxDNSAge
			flagActiveResolve = false
			flagActiveResolvers = ""
			flagDisableSNI = true
			flagUnsorted = false
			flagDebug = debug
			flagManifestOut = ""
			flagPostHooks = nil
			flagFleetScanWorkers = 0
			flagEnforcePrivateAsSource = false

			if err := runDNSExtract(&cobra.Command{}, nil); err != nil {
				t.Fatalf("runDNSExtract(debug=%v): %v", debug, err)
			}

			runEntries, err := os.ReadDir(filepath.Join(outputRoot, "net"))
			if err != nil {
				t.Fatalf("read network output dir: %v", err)
			}
			if len(runEntries) != 1 || !runEntries[0].IsDir() {
				t.Fatalf("run output entries = %#v, want one run directory", runEntries)
			}
			runDir := filepath.Join(outputRoot, "net", runEntries[0].Name())
			artifactPath := filepath.Join(runDir, "truncated-dns-packets.csv")

			manifestPath := filepath.Join(runDir, "_run-artifacts.json")
			manifestBytes, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var manifest RunArtifactsManifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}
			if !debug {
				if _, err := os.Stat(artifactPath); !os.IsNotExist(err) {
					t.Fatalf("non-debug truncated DNS artifact stat error = %v, want not exist", err)
				}
				if got, ok := manifest.Files["truncated_dns_packets"]; ok {
					t.Fatalf("non-debug manifest contains truncated_dns_packets = %q", got)
				}
			} else {
				f, err := os.Open(artifactPath)
				if err != nil {
					t.Fatalf("open truncated DNS artifact: %v", err)
				}
				records, err := csv.NewReader(f).ReadAll()
				f.Close()
				if err != nil {
					t.Fatalf("read truncated DNS artifact: %v", err)
				}
				if len(records) != 3 || records[1][2] != "api.exampl" || records[2][2] != "api.exampl" {
					t.Fatalf("unexpected truncated DNS CSV records: %#v", records)
				}
				if got := manifest.Files["truncated_dns_packets"]; got != artifactPath {
					t.Fatalf("manifest truncated_dns_packets = %q, want %q", got, artifactPath)
				}
			}

			unresolvedBytes, err := os.ReadFile(filepath.Join(runDir, "dns-unresolved-dns.txt"))
			if err != nil {
				t.Fatalf("read unresolved DNS artifact: %v", err)
			}
			unresolvedNames := unresolvedDNSNamesFromTable(string(unresolvedBytes))
			if !reflect.DeepEqual(unresolvedNames, []string{"api.example.com", "normal.example"}) {
				t.Fatalf("unresolved DNS names = %#v, want complete names only", unresolvedNames)
			}
		})
	}
}

func TestDnsextractFleetArtifactsRespectDebugAndProbeRename(t *testing.T) {
	restoreDNSExtractFlags(t)
	resolveDNSNamesIPv4 = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil
	}

	readDir := t.TempDir()
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.10\n"), 0o644); err != nil {
		t.Fatalf("write fleet file: %v", err)
	}

	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "non_debug", true: "debug"}[debug], func(t *testing.T) {
			outputRoot := t.TempDir()
			flagReadDir = readDir
			flagNetID = "net"
			flagOutputRoot = outputRoot
			flagFormat = "table"
			flagFleet = fleetPath
			flagExportCSV = ""
			flagConnectivityShort = false
			flagRadiusIMSI = false
			flagOnlyTCP = false
			flagIgnoreNTP = false
			flagExcludePorts = "53"
			flagFTPControlPorts = "21,990"
			flagFTPPassiveMinPort = "30000"
			flagServerSummaryExcludeUDPPorts = "33434-33534"
			flagDNSIPFile = ""
			flagTopologyDNSWindow = dns.DefaultTopologyBuildOptions().MaxDNSAge
			flagActiveResolve = false
			flagActiveResolvers = ""
			flagDisableSNI = true
			flagUnsorted = false
			flagDebug = debug
			flagManifestOut = ""
			flagPostHooks = nil
			flagFleetScanWorkers = 1
			flagEnforcePrivateAsSource = false

			if err := runDNSExtract(&cobra.Command{}, nil); err != nil {
				t.Fatalf("runDNSExtract(debug=%v): %v", debug, err)
			}
			runEntries, err := os.ReadDir(filepath.Join(outputRoot, "net"))
			if err != nil {
				t.Fatalf("read network output dir: %v", err)
			}
			if len(runEntries) != 1 || !runEntries[0].IsDir() {
				t.Fatalf("run output entries = %#v, want one run directory", runEntries)
			}
			runDir := filepath.Join(outputRoot, "net", runEntries[0].Name())
			manifestBytes, err := os.ReadFile(filepath.Join(runDir, "_run-artifacts.json"))
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var manifest RunArtifactsManifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}

			for _, artifact := range expectedSYNTrailArtifacts {
				got, present := manifest.Files[artifact.key]
				wantPresent := !artifact.debugOnly || debug
				if present != wantPresent {
					t.Fatalf("manifest key %q present=%v, want %v", artifact.key, present, wantPresent)
				}
				artifactPath := filepath.Join(runDir, artifact.filename)
				if wantPresent {
					if got != artifactPath {
						t.Fatalf("manifest key %q path = %q, want %q", artifact.key, got, artifactPath)
					}
					if _, err := os.Stat(artifactPath); err != nil {
						t.Fatalf("stat %s: %v", artifact.filename, err)
					}
				} else if _, err := os.Stat(artifactPath); !os.IsNotExist(err) {
					t.Fatalf("debug-only %s stat error = %v, want not exist", artifact.filename, err)
				}
			}
			if _, ok := manifest.Files["private_probes_syn_unique"]; ok {
				t.Fatal("manifest contains old key private_probes_syn_unique")
			}
			if _, err := os.Stat(filepath.Join(runDir, "private-probes-syn-unique.csv")); !os.IsNotExist(err) {
				t.Fatalf("old private probe filename stat error = %v, want not exist", err)
			}
		})
	}
}

func TestDnsextractReverseDNSLookupArtifactAndManifest(t *testing.T) {
	restoreDNSExtractFlags(t)
	resolveDNSNamesIPv4 = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil
	}

	readDir := t.TempDir()
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			lookupCalls := 0
			completeTopologyWithReverseDNS = func(
				_ context.Context,
				entries []dns.TopologyEntry,
				resolver *dns.ReverseResolver,
				options dns.ReverseDNSLookupOptions,
			) ([]dns.TopologyEntry, []dns.ReverseDNSLookupRecord, error) {
				lookupCalls++
				if resolver != nil {
					t.Fatalf("command resolver = %#v, want nil/default resolver", resolver)
				}
				out := append([]dns.TopologyEntry(nil), entries...)
				completed := false
				for i := range out {
					if out[i].DestinationIP == "8.8.8.8" && strings.TrimSpace(out[i].DNSName) == "" {
						out[i].DNSName = "ptr.example.com"
						out[i].DNSSource = "ptr+fcrdns+matrix"
						completed = true
					}
				}
				if !completed {
					t.Fatalf("test fixture has no unattributed 8.8.8.8 topology row: %#v", entries)
				}
				if options.Progress == nil {
					t.Fatal("command reverse DNS progress callback = nil")
				}
				options.Progress(1, 1)
				return out, []dns.ReverseDNSLookupRecord{{
					IP:               "8.8.8.8",
					Status:           "used_fcrdns",
					RawPTR:           "ptr.example.com",
					NormalizedName:   "ptr.example.com",
					Source:           "ptr+fcrdns+matrix",
					Reason:           "forward_confirmed",
					ForwardConfirmed: true,
					ForwardIPs:       "8.8.8.8",
				}}, nil
			}

			outputRoot := t.TempDir()
			flagReadDir = readDir
			flagNetID = "net"
			flagOutputRoot = outputRoot
			flagFormat = "table"
			flagFleet = ""
			flagExportCSV = ""
			flagConnectivityShort = false
			flagRadiusIMSI = false
			flagOnlyTCP = false
			flagIgnoreNTP = false
			flagExcludePorts = "53"
			flagFTPControlPorts = "21,990"
			flagFTPPassiveMinPort = "30000"
			flagServerSummaryExcludeUDPPorts = "33434-33534"
			flagDNSIPFile = ""
			flagTopologyDNSWindow = dns.DefaultTopologyBuildOptions().MaxDNSAge
			flagActiveResolve = false
			flagActiveResolvers = ""
			flagReverseDNSLookup = enabled
			flagDisableSNI = true
			flagUnsorted = false
			flagDebug = false
			flagManifestOut = ""
			flagPostHooks = nil
			flagFleetScanWorkers = 0
			flagEnforcePrivateAsSource = false

			if err := runDNSExtract(&cobra.Command{}, nil); err != nil {
				t.Fatalf("runDNSExtract(reverse-dns=%v): %v", enabled, err)
			}
			wantCalls := 0
			if enabled {
				wantCalls = 1
			}
			if lookupCalls != wantCalls {
				t.Fatalf("reverse DNS completion calls = %d, want %d", lookupCalls, wantCalls)
			}

			runEntries, err := os.ReadDir(filepath.Join(outputRoot, "net"))
			if err != nil {
				t.Fatalf("read network output dir: %v", err)
			}
			runDir := filepath.Join(outputRoot, "net", runEntries[0].Name())
			logPath := filepath.Join(runDir, "reverse-dns-lookup-log.csv")
			manifestBytes, err := os.ReadFile(filepath.Join(runDir, "_run-artifacts.json"))
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var manifest RunArtifactsManifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}
			if !enabled {
				if _, err := os.Stat(logPath); !os.IsNotExist(err) {
					t.Fatalf("disabled reverse DNS log stat error = %v, want not exist", err)
				}
				if _, ok := manifest.Files["reverse_dns_lookup_log"]; ok {
					t.Fatal("disabled manifest contains reverse_dns_lookup_log")
				}
				return
			}

			logBytes, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read reverse DNS log: %v", err)
			}
			if !strings.Contains(string(logBytes), "8.8.8.8,used_fcrdns,ptr.example.com") {
				t.Fatalf("reverse DNS log missing result: %s", logBytes)
			}
			if got := manifest.Files["reverse_dns_lookup_log"]; got != logPath {
				t.Fatalf("manifest reverse DNS path = %q, want %q", got, logPath)
			}
			for _, filename := range []string{"network-topology-matrix.txt", "network-topology-matrix.json", "network-topology-matrix.compact.json", "service-endpoints.txt"} {
				contents, err := os.ReadFile(filepath.Join(runDir, filename))
				if err != nil {
					t.Fatalf("read %s: %v", filename, err)
				}
				if !strings.Contains(string(contents), "ptr.example.com") {
					t.Fatalf("%s does not contain reverse DNS completion: %s", filename, contents)
				}
			}
			unresolvedBytes, err := os.ReadFile(filepath.Join(runDir, "dns-unresolved-dns.txt"))
			if err != nil {
				t.Fatalf("read unresolved DNS artifact: %v", err)
			}
			if got := unresolvedDNSNamesFromTable(string(unresolvedBytes)); !reflect.DeepEqual(got, []string{"api.example.com", "normal.example"}) {
				t.Fatalf("PTR completion changed unresolved DNS artifact: %#v", got)
			}
		})
	}
}

func restoreDNSExtractFlags(t *testing.T) {
	t.Helper()
	oldReadDir, oldFleet := flagReadDir, flagFleet
	oldFormat, oldExportCSV := flagFormat, flagExportCSV
	oldConnectivityShort, oldRadiusIMSI := flagConnectivityShort, flagRadiusIMSI
	oldOnlyTCP, oldIgnoreNTP := flagOnlyTCP, flagIgnoreNTP
	oldExcludePorts, oldFTPControlPorts := flagExcludePorts, flagFTPControlPorts
	oldFTPPassiveMinPort := flagFTPPassiveMinPort
	oldServerSummaryExcludeUDPPorts := flagServerSummaryExcludeUDPPorts
	oldDNSIPFile, oldTopologyDNSWindow := flagDNSIPFile, flagTopologyDNSWindow
	oldActiveResolve, oldActiveResolvers := flagActiveResolve, flagActiveResolvers
	oldReverseDNSLookup := flagReverseDNSLookup
	oldDisableSNI, oldUnsorted, oldDebug := flagDisableSNI, flagUnsorted, flagDebug
	oldManifestOut := flagManifestOut
	oldPostHooks := append([]string(nil), flagPostHooks...)
	oldFleetScanWorkers := flagFleetScanWorkers
	oldNetID, oldOutputRoot := flagNetID, flagOutputRoot
	oldEnforcePrivateAsSource := flagEnforcePrivateAsSource
	oldResolveDNSNamesIPv4 := resolveDNSNamesIPv4
	oldCompleteTopologyWithReverseDNS := completeTopologyWithReverseDNS
	t.Cleanup(func() {
		flagReadDir, flagFleet = oldReadDir, oldFleet
		flagFormat, flagExportCSV = oldFormat, oldExportCSV
		flagConnectivityShort, flagRadiusIMSI = oldConnectivityShort, oldRadiusIMSI
		flagOnlyTCP, flagIgnoreNTP = oldOnlyTCP, oldIgnoreNTP
		flagExcludePorts, flagFTPControlPorts = oldExcludePorts, oldFTPControlPorts
		flagFTPPassiveMinPort = oldFTPPassiveMinPort
		flagServerSummaryExcludeUDPPorts = oldServerSummaryExcludeUDPPorts
		flagDNSIPFile, flagTopologyDNSWindow = oldDNSIPFile, oldTopologyDNSWindow
		flagActiveResolve, flagActiveResolvers = oldActiveResolve, oldActiveResolvers
		flagReverseDNSLookup = oldReverseDNSLookup
		flagDisableSNI, flagUnsorted, flagDebug = oldDisableSNI, oldUnsorted, oldDebug
		flagManifestOut = oldManifestOut
		flagPostHooks = oldPostHooks
		flagFleetScanWorkers = oldFleetScanWorkers
		flagNetID, flagOutputRoot = oldNetID, oldOutputRoot
		flagEnforcePrivateAsSource = oldEnforcePrivateAsSource
		resolveDNSNamesIPv4 = oldResolveDNSNamesIPv4
		completeTopologyWithReverseDNS = oldCompleteTopologyWithReverseDNS
	})
}

func TestActiveResolveFiltersFinalUnresolvedWritesCompactMatrixWithoutMutatingDNSIP(t *testing.T) {
	restoreDNSExtractFlags(t)

	readDir := t.TempDir()
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))
	outputRoot := t.TempDir()
	dnsIPPath := filepath.Join(t.TempDir(), "dns-ip.csv")
	wantDNSIP := "seed.example,9.9.9.9\n"
	if err := os.WriteFile(dnsIPPath, []byte(wantDNSIP), 0o644); err != nil {
		t.Fatalf("write dns-ip file: %v", err)
	}

	var resolverCalls int
	resolveDNSNamesIPv4 = func(
		_ context.Context,
		names []string,
		_ dns.ResolveUnresolvedOptions,
		lookup dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, error) {
		resolverCalls++
		if lookup != nil {
			t.Fatalf("command supplied unexpected lookup override")
		}
		if !reflect.DeepEqual(names, []string{"api.example.com", "normal.example"}) {
			t.Fatalf("active resolve names = %#v", names)
		}
		return []dns.DNSNameIPv4Resolution{
			{DNSName: "normal.example", IPv4s: []string{"8.8.8.8"}},
		}, nil
	}

	flagReadDir = readDir
	flagNetID = "net"
	flagOutputRoot = outputRoot
	flagFormat = "table"
	flagFleet = ""
	flagExportCSV = ""
	flagConnectivityShort = false
	flagRadiusIMSI = false
	flagOnlyTCP = false
	flagIgnoreNTP = false
	flagExcludePorts = "53"
	flagFTPControlPorts = "21,990"
	flagFTPPassiveMinPort = "30000"
	flagServerSummaryExcludeUDPPorts = "33434-33534"
	flagDNSIPFile = dnsIPPath
	flagTopologyDNSWindow = dns.DefaultTopologyBuildOptions().MaxDNSAge
	flagActiveResolve = true
	flagActiveResolvers = ""
	flagDisableSNI = true
	flagUnsorted = false
	flagDebug = false
	flagManifestOut = ""
	flagPostHooks = nil
	flagFleetScanWorkers = 0
	flagEnforcePrivateAsSource = false

	if err := runDNSExtract(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runDNSExtract: %v", err)
	}
	if resolverCalls != 1 {
		t.Fatalf("active resolver calls = %d, want 1", resolverCalls)
	}

	runEntries, err := os.ReadDir(filepath.Join(outputRoot, "net"))
	if err != nil {
		t.Fatalf("read network output dir: %v", err)
	}
	if len(runEntries) != 1 || !runEntries[0].IsDir() {
		t.Fatalf("run output entries = %#v, want one run directory", runEntries)
	}
	runDir := filepath.Join(outputRoot, "net", runEntries[0].Name())

	matrixBytes, err := os.ReadFile(filepath.Join(runDir, "network-topology-matrix.txt"))
	if err != nil {
		t.Fatalf("read network topology matrix: %v", err)
	}
	matrix := string(matrixBytes)
	if !strings.Contains(matrix, "normal.example") || !strings.Contains(matrix, "active+matrix") {
		t.Fatalf("active matrix completion missing from topology:\n%s", matrix)
	}
	compactMatrixPath := filepath.Join(runDir, "network-topology-matrix.compact.json")
	compactMatrixBytes, err := os.ReadFile(compactMatrixPath)
	if err != nil {
		t.Fatalf("read compact network topology matrix: %v", err)
	}
	var compactMatrix struct {
		Version int    `json:"version"`
		Layout  string `json:"layout"`
	}
	if err := json.Unmarshal(compactMatrixBytes, &compactMatrix); err != nil {
		t.Fatalf("unmarshal compact network topology matrix: %v", err)
	}
	if compactMatrix.Version != 2 || compactMatrix.Layout != "dict_by_issuer" {
		t.Fatalf("compact matrix metadata = %#v", compactMatrix)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(runDir, "_run-artifacts.json"))
	if err != nil {
		t.Fatalf("read run artifact manifest: %v", err)
	}
	var manifest RunArtifactsManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("unmarshal run artifact manifest: %v", err)
	}
	if got := manifest.Files["network_topology_matrix_compact"]; got != compactMatrixPath {
		t.Fatalf("manifest compact matrix path = %q, want %q", got, compactMatrixPath)
	}

	unresolvedBytes, err := os.ReadFile(filepath.Join(runDir, "dns-unresolved-dns.txt"))
	if err != nil {
		t.Fatalf("read unresolved DNS artifact: %v", err)
	}
	if got := unresolvedDNSNamesFromTable(string(unresolvedBytes)); !reflect.DeepEqual(got, []string{"api.example.com"}) {
		t.Fatalf("final unresolved DNS names = %#v, want only names absent from final topology", got)
	}

	serviceBytes, err := os.ReadFile(filepath.Join(runDir, "service-endpoints.txt"))
	if err != nil {
		t.Fatalf("read service endpoints: %v", err)
	}
	var endpoints []dns.ServiceEndpoint
	if err := json.Unmarshal(serviceBytes, &endpoints); err != nil {
		t.Fatalf("unmarshal service endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].IP != "8.8.8.8" || endpoints[0].DNS != "normal.example" {
		t.Fatalf("service endpoints = %#v, want active-completed endpoint", endpoints)
	}

	dnsIPBytes, err := os.ReadFile(dnsIPPath)
	if err != nil {
		t.Fatalf("read dns-ip file: %v", err)
	}
	if string(dnsIPBytes) != wantDNSIP {
		t.Fatalf("dns-ip file changed by active completion: %q", dnsIPBytes)
	}
}

func writeDNSArtifactTestPCAP(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatalf("write test pcap header: %v", err)
	}

	truncated := make([]byte, 12)
	binary.BigEndian.PutUint16(truncated[0:2], 0x1234)
	binary.BigEndian.PutUint16(truncated[2:4], 0x0100)
	binary.BigEndian.PutUint16(truncated[4:6], 1)
	truncated = append(truncated, 0x03, 'a', 'p', 'i', 0x07, 'e', 'x', 'a', 'm', 'p', 'l')
	payloads := [][]byte{
		truncated,
		append([]byte(nil), truncated...),
		buildDNSArtifactTestQuery("api.example.com"),
		buildDNSArtifactTestQuery("normal.example"),
	}
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for i, payload := range payloads {
		packetData := buildDNSArtifactTestPacket(t, payload)
		originalLength := len(packetData)
		if i < 2 {
			originalLength += 8
		}
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			CaptureLength: len(packetData),
			Length:        originalLength,
		}, packetData); err != nil {
			f.Close()
			t.Fatalf("write test pcap packet %d: %v", i, err)
		}
	}
	connectionPackets := [][]byte{
		buildDNSArtifactTestTCPPacket(t, false),
		buildDNSArtifactTestTCPPacket(t, true),
	}
	for i, packetData := range connectionPackets {
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(len(payloads)+i) * time.Second),
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}, packetData); err != nil {
			f.Close()
			t.Fatalf("write test connection packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close test pcap: %v", err)
	}
}

func buildDNSArtifactTestTCPPacket(t *testing.T, response bool) []byte {
	t.Helper()
	srcIP := net.ParseIP("10.0.0.10").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	srcPort, dstPort := layers.TCPPort(40000), layers.TCPPort(443)
	if response {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, SYN: true, ACK: response, Seq: 1}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set TCP checksum network layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip4,
		tcp,
	); err != nil {
		t.Fatalf("serialize test TCP packet: %v", err)
	}
	return buf.Bytes()
}

func buildDNSArtifactTestQuery(name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x090a)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, byte(layers.DNSTypeA), 0, 1)
	return msg
}

func buildDNSArtifactTestPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.10").To4(),
		DstIP:    net.ParseIP("192.0.2.53").To4(),
	}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set UDP checksum network layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip4,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize test DNS packet: %v", err)
	}
	return buf.Bytes()
}

func unresolvedDNSNamesFromTable(table string) []string {
	var names []string
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || net.ParseIP(fields[1]) == nil {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

func TestTruncatedDNSPacketsArtifactIsHeaderOnlyWhenEmpty(t *testing.T) {
	om, err := NewOutputManager("net", t.TempDir())
	if err != nil {
		t.Fatalf("NewOutputManager: %v", err)
	}
	artifactPath, err := writeTruncatedDNSPacketsCSV(om, nil)
	if err != nil {
		t.Fatalf("writeTruncatedDNSPacketsCSV: %v", err)
	}
	f, err := os.Open(artifactPath)
	if err != nil {
		t.Fatalf("open truncated DNS artifact: %v", err)
	}
	records, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil {
		t.Fatalf("read truncated DNS artifact: %v", err)
	}
	if len(records) != 1 || records[0][2] != "truncated_dns_name" {
		t.Fatalf("unexpected header-only truncated DNS artifact: %#v", records)
	}
}

func TestDnsextractFleetScanWorkersDefaultIsAuto(t *testing.T) {
	cmd := dnsextractCommandForTest(t)
	flag := cmd.Flags().Lookup("fleet-scan-workers")
	if flag == nil {
		t.Fatal("dnsextract missing --fleet-scan-workers flag")
	}
	if flag.DefValue != "0" {
		t.Fatalf("--fleet-scan-workers default = %q, want 0", flag.DefValue)
	}
}

func TestDnsextractFleetScanWorkersValidationAcceptsZero(t *testing.T) {
	if err := validateFleetScanWorkers("fleet.txt", 0); err != nil {
		t.Fatalf("validateFleetScanWorkers() error = %v, want nil", err)
	}
}

func TestDnsextractFleetScanWorkersValidationRejectsNegative(t *testing.T) {
	if err := validateFleetScanWorkers("fleet.txt", -2); err == nil {
		t.Fatal("validateFleetScanWorkers() error = nil, want error")
	}
}

func TestDnsextractFleetScanWorkersIgnoredWithoutFleet(t *testing.T) {
	if err := validateFleetScanWorkers("", 8); err != nil {
		t.Fatalf("validateFleetScanWorkers() without fleet error = %v, want nil", err)
	}
}

func TestDnsextractEffectiveFleetScanWorkers(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(old)
	})

	tests := []struct {
		name      string
		requested int
		fileCount int
		want      int
	}{
		{name: "auto no files", requested: 0, fileCount: 0, want: 1},
		{name: "auto one file", requested: 0, fileCount: 1, want: 1},
		{name: "auto caps at gomaxprocs", requested: 0, fileCount: 10, want: 4},
		{name: "explicit one", requested: 1, fileCount: 10, want: 1},
		{name: "explicit many", requested: 8, fileCount: 2, want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveFleetScanWorkers(tt.requested, tt.fileCount); got != tt.want {
				t.Fatalf("effectiveFleetScanWorkers(%d, %d) = %d, want %d", tt.requested, tt.fileCount, got, tt.want)
			}
		})
	}
}

func TestDnsextractFleetScanWorkersPassedToSYNTrailScanner(t *testing.T) {
	origScan := scanSYNTrailFilesWithOptions
	t.Cleanup(func() {
		scanSYNTrailFilesWithOptions = origScan
	})

	wantFiles := []string{
		filepath.Join(t.TempDir(), "a.pcap"),
		filepath.Join(t.TempDir(), "b.pcapng"),
	}
	var (
		gotFiles        []string
		gotOpt          syntrail.ScanOptions
		called          bool
		progressUpdates []fleetProgressUpdate
	)
	scanSYNTrailFilesWithOptions = func(ctx context.Context, files []string, opt syntrail.ScanOptions) ([]syntrail.Record, error) {
		called = true
		gotFiles = append([]string(nil), files...)
		gotOpt = opt
		if opt.Progress != nil {
			opt.Progress(1, len(files), files[0])
		}
		return []syntrail.Record{
			{
				SrcIP:     netip.MustParseAddr("10.0.0.1"),
				DstIP:     netip.MustParseAddr("203.0.113.10"),
				DstPort:   443,
				Protocol:  syntrail.ProtocolTCP,
				Timestamp: time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC),
			},
		}, nil
	}

	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n"), 0o644); err != nil {
		t.Fatalf("write fleet file: %v", err)
	}

	artifacts, err := runSYNTrailSidecar(
		context.Background(),
		newSYNTrailTestOutputManager(t),
		wantFiles,
		fleetPath,
		synTrailArtifactOptions{
			ScanOptions: syntrail.ScanOptions{
				Workers: 8,
				Progress: func(done, total int, file string) {
					progressUpdates = append(progressUpdates, fleetProgressUpdate{done: done, total: total, file: file})
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("runSYNTrailSidecar() error = %v", err)
	}
	if !called {
		t.Fatal("syntrail scanner was not called")
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("scanner files = %#v, want %#v", gotFiles, wantFiles)
	}
	if gotOpt.Workers != 8 {
		t.Fatalf("scanner Workers = %d, want 8", gotOpt.Workers)
	}
	if gotOpt.Progress == nil {
		t.Fatal("scanner Progress callback = nil, want non-nil")
	}
	wantProgress := []fleetProgressUpdate{
		{done: 1, total: 2, file: wantFiles[0]},
		{done: 2, total: 2, file: ""},
	}
	if !reflect.DeepEqual(progressUpdates, wantProgress) {
		t.Fatalf("progress updates = %#v, want %#v", progressUpdates, wantProgress)
	}
	if len(artifacts) == 0 {
		t.Fatal("runSYNTrailSidecar() returned no artifacts")
	}
}

func TestDnsextractFleetTrailScanProgressMessages(t *testing.T) {
	var updates []progressBarUpdate
	cb := fleetTrailScanProgress(func(done, total int, message string) {
		updates = append(updates, progressBarUpdate{done: done, total: total, message: message})
	})

	cb(1, 2, filepath.Join("captures", "a.pcap"))
	cb(2, 2, "")

	want := []progressBarUpdate{
		{done: 1, total: 2, message: "Fleet trail a.pcap"},
		{done: 2, total: 2, message: "Fleet trail scan complete"},
	}
	if !reflect.DeepEqual(updates, want) {
		t.Fatalf("progress messages = %#v, want %#v", updates, want)
	}
}

func dnsextractCommandForTest(t *testing.T) *cobra.Command {
	t.Helper()
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "dnsextract" {
			return cmd
		}
	}
	t.Fatal("dnsextract command not found")
	return nil
}

type fleetProgressUpdate struct {
	done  int
	total int
	file  string
}

type progressBarUpdate struct {
	done    int
	total   int
	message string
}
