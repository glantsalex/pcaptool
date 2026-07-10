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
	resolveDNSNamesIPv4WithAudit = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, []dns.ActiveResolveAuditRecord, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil, nil
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

			runDir := findSingleRunDir(t, outputRoot, "net")
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
			if manifest.PCAPDate != "2026-06-28" {
				t.Fatalf("manifest pcap_date = %q, want 2026-06-28", manifest.PCAPDate)
			}
			if manifest.OutputDir != runDir || manifest.RunDir != runDir {
				t.Fatalf("manifest output dirs = output_dir %q run_dir %q, want %q", manifest.OutputDir, manifest.RunDir, runDir)
			}
			if manifest.RunID != filepath.Base(runDir) || !strings.HasPrefix(manifest.RunID, "run-") {
				t.Fatalf("manifest run_id = %q, run dir = %q", manifest.RunID, runDir)
			}
			servicesPath := filepath.Join(runDir, "unique-dns-port-proto.csv")
			if got := manifest.Files["unique_dns_port_proto"]; got != servicesPath {
				t.Fatalf("manifest unique_dns_port_proto = %q, want %q", got, servicesPath)
			}
			if _, exists := manifest.Files["network_topology_services"]; exists {
				t.Fatal("manifest contains retired network_topology_services key")
			}
			if _, exists := manifest.Files["active_resolve_log"]; exists {
				t.Fatal("manifest contains active_resolve_log while --active-resolve=false")
			}
			if _, err := os.Stat(filepath.Join(runDir, "active-resolve-log.csv")); !os.IsNotExist(err) {
				t.Fatalf("disabled active-resolve-log.csv stat error = %v, want not exist", err)
			}
			if _, err := os.Stat(filepath.Join(runDir, "network-topology-services.csv")); !os.IsNotExist(err) {
				t.Fatalf("retired network-topology-services.csv stat error = %v, want not exist", err)
			}
			servicesFile, err := os.Open(servicesPath)
			if err != nil {
				t.Fatalf("open unique DNS/port/protocol CSV: %v", err)
			}
			servicesRows, readErr := csv.NewReader(servicesFile).ReadAll()
			closeErr := servicesFile.Close()
			if readErr != nil {
				t.Fatalf("read unique DNS/port/protocol CSV: %v", readErr)
			}
			if closeErr != nil {
				t.Fatalf("close unique DNS/port/protocol CSV: %v", closeErr)
			}
			if len(servicesRows) < 2 || !reflect.DeepEqual(servicesRows[0], []string{"dns", "port", "protocol"}) {
				t.Fatalf("unique DNS/port/protocol rows = %#v, want header and data", servicesRows)
			}
			for key, path := range manifest.Files {
				if !strings.HasPrefix(path, runDir+string(os.PathSeparator)) {
					t.Fatalf("manifest file %q path = %q, want under %q", key, path, runDir)
				}
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
	resolveDNSNamesIPv4WithAudit = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, []dns.ActiveResolveAuditRecord, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil, nil
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
			runDir := findSingleRunDir(t, outputRoot, "net")
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
	resolveDNSNamesIPv4WithAudit = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, []dns.ActiveResolveAuditRecord, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil, nil
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

			runDir := findSingleRunDir(t, outputRoot, "net")
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

func TestDnsextractTLSCertLookupDecoratesExactEndpointAndIsManifested(t *testing.T) {
	restoreDNSExtractFlags(t)
	resolveDNSNamesIPv4WithAudit = func(
		context.Context,
		[]string,
		dns.ResolveUnresolvedOptions,
		dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, []dns.ActiveResolveAuditRecord, error) {
		t.Fatal("active resolver called while --active-resolve=false")
		return nil, nil, nil
	}

	readDir := t.TempDir()
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))
	probeCalls := 0
	probeTLSCertificates = func(
		_ context.Context,
		entries []dns.TopologyEntry,
		prober dns.TLSCertProber,
		options dns.TLSCertLookupOptions,
	) ([]dns.TLSCertLookupRecord, error) {
		probeCalls++
		if prober != nil {
			t.Fatalf("command TLS certificate prober = %#v, want nil/default", prober)
		}
		if len(entries) == 0 {
			t.Fatal("command passed empty topology to TLS certificate lookup")
		}
		if options.Progress == nil {
			t.Fatal("command TLS certificate progress callback = nil")
		}
		if options.Timeout != 23*time.Second {
			t.Fatalf("command TLS certificate timeout = %s, want 23s", options.Timeout)
		}
		options.Progress(1, 1)
		return []dns.TLSCertLookupRecord{{
			IP:               "8.8.8.8",
			Port:             443,
			Status:           "used_cert",
			SelectedName:     "cert.example.com",
			Reason:           "selected_first_san",
			SubjectCN:        "cert.example.com",
			DNSSANs:          "cert.example.com",
			IssuerCommonName: "Test Issuer",
			NotBefore:        "2026-01-01T00:00:00Z",
			NotAfter:         "2027-01-01T00:00:00Z",
			Source:           "tls-cert-san+matrix",
		}}, nil
	}

	type runResult struct {
		runDir   string
		manifest RunArtifactsManifest
		files    map[string][]byte
	}
	run := func(t *testing.T, enabled bool) runResult {
		t.Helper()
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
		flagReverseDNSLookup = false
		flagTLSCertLookup = enabled
		flagTLSCertLookupTimeoutSeconds = 23
		flagDisableSNI = true
		flagUnsorted = false
		flagDebug = false
		flagManifestOut = ""
		flagPostHooks = nil
		flagFleetScanWorkers = 0
		flagEnforcePrivateAsSource = false

		if err := runDNSExtract(&cobra.Command{}, nil); err != nil {
			t.Fatalf("runDNSExtract(tls-cert-lookup=%v): %v", enabled, err)
		}
		runDir := findSingleRunDir(t, outputRoot, "net")
		manifestBytes, err := os.ReadFile(filepath.Join(runDir, "_run-artifacts.json"))
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		var manifest RunArtifactsManifest
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			t.Fatalf("unmarshal manifest: %v", err)
		}
		files := make(map[string][]byte)
		for _, filename := range []string{
			"network-topology-matrix.txt",
			"network-topology-matrix.json",
			"network-topology-matrix.compact.json",
			"unique-dns-port-proto.csv",
			"service-endpoints.txt",
		} {
			contents, err := os.ReadFile(filepath.Join(runDir, filename))
			if err != nil {
				t.Fatalf("read %s: %v", filename, err)
			}
			files[filename] = contents
		}
		return runResult{runDir: runDir, manifest: manifest, files: files}
	}

	disabled := run(t, false)
	if probeCalls != 0 {
		t.Fatalf("disabled TLS certificate probe calls = %d, want 0", probeCalls)
	}
	disabledLogPath := filepath.Join(disabled.runDir, "tls-cert-lookup-log.csv")
	if _, err := os.Stat(disabledLogPath); !os.IsNotExist(err) {
		t.Fatalf("disabled TLS certificate log stat error = %v, want not exist", err)
	}
	if _, ok := disabled.manifest.Files["tls_cert_lookup_log"]; ok {
		t.Fatal("disabled manifest contains tls_cert_lookup_log")
	}

	enabled := run(t, true)
	if probeCalls != 1 {
		t.Fatalf("enabled TLS certificate probe calls = %d, want 1", probeCalls)
	}
	enabledLogPath := filepath.Join(enabled.runDir, "tls-cert-lookup-log.csv")
	logBytes, err := os.ReadFile(enabledLogPath)
	if err != nil {
		t.Fatalf("read enabled TLS certificate log: %v", err)
	}
	if !strings.Contains(string(logBytes), "8.8.8.8,443,used_cert,cert.example.com") || !strings.Contains(string(logBytes), "tls-cert-san+matrix") {
		t.Fatalf("TLS certificate log missing result: %s", logBytes)
	}
	if got := enabled.manifest.Files["tls_cert_lookup_log"]; got != enabledLogPath {
		t.Fatalf("manifest TLS certificate log path = %q, want %q", got, enabledLogPath)
	}
	for _, filename := range []string{"network-topology-matrix.txt", "network-topology-matrix.json", "network-topology-matrix.compact.json", "unique-dns-port-proto.csv", "service-endpoints.txt"} {
		if strings.Contains(string(disabled.files[filename]), "cert.example.com") || strings.Contains(string(disabled.files[filename]), "tls-cert-san+matrix") {
			t.Fatalf("disabled %s unexpectedly contains TLS certificate decoration: %s", filename, disabled.files[filename])
		}
		if !strings.Contains(string(enabled.files[filename]), "cert.example.com") {
			t.Fatalf("enabled %s missing TLS certificate name: %s", filename, enabled.files[filename])
		}
		if filename != "service-endpoints.txt" && filename != "unique-dns-port-proto.csv" && !strings.Contains(string(enabled.files[filename]), "tls-cert-san+matrix") {
			t.Fatalf("enabled %s missing TLS certificate source: %s", filename, enabled.files[filename])
		}
	}
}

func restoreDNSExtractFlags(t *testing.T) {
	t.Helper()
	oldReadDir, oldFleet := flagReadDir, flagFleet
	oldFormat, oldExportCSV := flagFormat, flagExportCSV
	oldConnectivityShort, oldRadiusIMSI := flagConnectivityShort, flagRadiusIMSI
	oldOnlyTCP, oldInferDNSFromConnections, oldIgnoreNTP := flagOnlyTCP, flagInferDNSFromConnections, flagIgnoreNTP
	oldExcludePorts, oldFTPControlPorts := flagExcludePorts, flagFTPControlPorts
	oldFTPPassiveMinPort := flagFTPPassiveMinPort
	oldServerSummaryExcludeUDPPorts := flagServerSummaryExcludeUDPPorts
	oldDNSIPFile, oldTopologyDNSWindow := flagDNSIPFile, flagTopologyDNSWindow
	oldActiveResolve, oldActiveResolvers := flagActiveResolve, flagActiveResolvers
	oldReverseDNSLookup := flagReverseDNSLookup
	oldTLSCertLookup := flagTLSCertLookup
	oldTLSCertLookupTimeoutSeconds := flagTLSCertLookupTimeoutSeconds
	oldDisableSNI, oldUnsorted, oldDebug := flagDisableSNI, flagUnsorted, flagDebug
	oldManifestOut := flagManifestOut
	oldPostHooks := append([]string(nil), flagPostHooks...)
	oldFleetScanWorkers := flagFleetScanWorkers
	oldNetID, oldOutputRoot := flagNetID, flagOutputRoot
	oldEnforcePrivateAsSource := flagEnforcePrivateAsSource
	oldResolveDNSNamesIPv4WithAudit := resolveDNSNamesIPv4WithAudit
	oldCompleteTopologyWithReverseDNS := completeTopologyWithReverseDNS
	oldProbeTLSCertificates := probeTLSCertificates
	t.Cleanup(func() {
		flagReadDir, flagFleet = oldReadDir, oldFleet
		flagFormat, flagExportCSV = oldFormat, oldExportCSV
		flagConnectivityShort, flagRadiusIMSI = oldConnectivityShort, oldRadiusIMSI
		flagOnlyTCP, flagInferDNSFromConnections, flagIgnoreNTP = oldOnlyTCP, oldInferDNSFromConnections, oldIgnoreNTP
		flagExcludePorts, flagFTPControlPorts = oldExcludePorts, oldFTPControlPorts
		flagFTPPassiveMinPort = oldFTPPassiveMinPort
		flagServerSummaryExcludeUDPPorts = oldServerSummaryExcludeUDPPorts
		flagDNSIPFile, flagTopologyDNSWindow = oldDNSIPFile, oldTopologyDNSWindow
		flagActiveResolve, flagActiveResolvers = oldActiveResolve, oldActiveResolvers
		flagReverseDNSLookup = oldReverseDNSLookup
		flagTLSCertLookup = oldTLSCertLookup
		flagTLSCertLookupTimeoutSeconds = oldTLSCertLookupTimeoutSeconds
		flagDisableSNI, flagUnsorted, flagDebug = oldDisableSNI, oldUnsorted, oldDebug
		flagManifestOut = oldManifestOut
		flagPostHooks = oldPostHooks
		flagFleetScanWorkers = oldFleetScanWorkers
		flagNetID, flagOutputRoot = oldNetID, oldOutputRoot
		flagEnforcePrivateAsSource = oldEnforcePrivateAsSource
		resolveDNSNamesIPv4WithAudit = oldResolveDNSNamesIPv4WithAudit
		completeTopologyWithReverseDNS = oldCompleteTopologyWithReverseDNS
		probeTLSCertificates = oldProbeTLSCertificates
	})
}

func TestTLSCertLookupTimeoutFlagAndValidation(t *testing.T) {
	restoreDNSExtractFlags(t)
	flag := dnsextractCommandForTest(t).Flags().Lookup("tls-cert-lookup-timeout")
	if flag == nil {
		t.Fatal("--tls-cert-lookup-timeout flag not found")
	}
	if flag.DefValue != "15" || flag.Value.Type() != "int" {
		t.Fatalf("flag default/type = %q/%q, want 15/int", flag.DefValue, flag.Value.Type())
	}
	for _, value := range []string{"abc", "45.6"} {
		if err := flag.Value.Set(value); err == nil {
			t.Fatalf("setting --tls-cert-lookup-timeout=%q succeeded, want integer parse error", value)
		}
	}

	for _, tc := range []struct {
		seconds int
		wantErr bool
	}{
		{seconds: 4, wantErr: true},
		{seconds: 5},
		{seconds: 15},
		{seconds: 30},
		{seconds: 31, wantErr: true},
	} {
		err := validateTLSCertLookupTimeout(tc.seconds)
		if (err != nil) != tc.wantErr {
			t.Fatalf("validateTLSCertLookupTimeout(%d) error = %v, wantErr %v", tc.seconds, err, tc.wantErr)
		}
	}
}

func TestInferDNSFromConnectionsFlagDefault(t *testing.T) {
	restoreDNSExtractFlags(t)
	flag := dnsextractCommandForTest(t).Flags().Lookup("infer-dns-from-connections")
	if flag == nil {
		t.Fatal("--infer-dns-from-connections flag not found")
	}
	if flag.DefValue != "false" || flag.Value.Type() != "bool" {
		t.Fatalf("flag default/type = %q/%q, want false/bool", flag.DefValue, flag.Value.Type())
	}
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
	resolveDNSNamesIPv4WithAudit = func(
		_ context.Context,
		names []string,
		_ dns.ResolveUnresolvedOptions,
		lookup dns.IPv4LookupFunc,
	) ([]dns.DNSNameIPv4Resolution, []dns.ActiveResolveAuditRecord, error) {
		resolverCalls++
		if lookup != nil {
			t.Fatalf("command supplied unexpected lookup override")
		}
		if !reflect.DeepEqual(names, []string{"api.example.com", "normal.example"}) {
			t.Fatalf("active resolve names = %#v", names)
		}
		resolutions := []dns.DNSNameIPv4Resolution{
			{DNSName: "normal.example", IPv4s: []string{"8.8.8.8"}},
		}
		return resolutions, []dns.ActiveResolveAuditRecord{
			{DNSName: "api.example.com", Status: "error", Error: "lookup failed"},
			{DNSName: "normal.example", Status: "resolved", IPv4s: []string{"8.8.8.8"}},
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

	runDir := findSingleRunDir(t, outputRoot, "net")
	activeResolveLogPath := filepath.Join(runDir, "active-resolve-log.csv")
	activeResolveLog, err := os.ReadFile(activeResolveLogPath)
	if err != nil {
		t.Fatalf("read active resolve log: %v", err)
	}
	for _, want := range []string{
		"dns_name,status,configured_resolvers,timeout_seconds,ipv4_answers,matrix_ips,matrix_rows_completed,error",
		"api.example.com,error,8.8.8.8;1.1.1.1,10,,,0,lookup failed",
		"normal.example,resolved,8.8.8.8;1.1.1.1,10,8.8.8.8,8.8.8.8,1,",
	} {
		if !strings.Contains(string(activeResolveLog), want) {
			t.Fatalf("active resolve log missing %q:\n%s", want, activeResolveLog)
		}
	}

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
	if got := manifest.Files["active_resolve_log"]; got != activeResolveLogPath {
		t.Fatalf("manifest active resolve log path = %q, want %q", got, activeResolveLogPath)
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

func findSingleRunDir(t *testing.T, outputRoot, netID string) string {
	t.Helper()
	netDir := filepath.Join(outputRoot, netID)
	dateEntries, err := os.ReadDir(netDir)
	if err != nil {
		t.Fatalf("read network output dir %s: %v", netDir, err)
	}
	if len(dateEntries) != 1 || !dateEntries[0].IsDir() || !strings.HasPrefix(dateEntries[0].Name(), "pcap-date-") {
		t.Fatalf("date output entries = %#v, want one pcap-date-* directory", dateEntries)
	}
	dateDir := filepath.Join(netDir, dateEntries[0].Name())
	runEntries, err := os.ReadDir(dateDir)
	if err != nil {
		t.Fatalf("read PCAP-date output dir %s: %v", dateDir, err)
	}
	if len(runEntries) != 1 || !runEntries[0].IsDir() || !strings.HasPrefix(runEntries[0].Name(), "run-") {
		t.Fatalf("run output entries = %#v, want one run-* directory", runEntries)
	}
	return filepath.Join(dateDir, runEntries[0].Name())
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
