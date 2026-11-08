package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/logicalservice"
	"github.com/aglants/pcaptool/internal/lsm"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func lsmTestDefinitions(t *testing.T) (string, *logicalservice.Definitions) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services.yaml")
	content := `schema_version: 1
services:
  - id: example_platform
    name: Example platform
rules:
  - id: example_platform
    priority: 100
    service_id: example_platform
    match:
      dns_suffix: [example.com]
      transports:
        - proto: tcp
          ports: [443]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	defs, err := logicalservice.LoadDefinitions(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, defs
}

func readLSMJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

func TestLSMArtifactsRoundTripAndFailureCleanup(t *testing.T) {
	_, defs := lsmTestDefinitions(t)
	now := time.Date(2026, 10, 10, 12, 0, 0, 123456789, time.UTC)
	rows := []dns.TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "api.example.com", Protocol: "tcp", Port: 443, ObservedAt: now},
		{IssuerIP: "10.0.0.1", DestinationIP: "1.1.1.1", Protocol: "udp", Port: 443, ObservedAt: now},
		{IssuerIP: "10.0.0.2", DestinationIP: "192.168.1.1", Protocol: "tcp", Port: 443, ObservedAt: now},
	}
	om, err := NewOutputManagerForRun("stream-1", t.TempDir(), now, now)
	if err != nil {
		t.Fatal(err)
	}
	paths, stats, err := writeLSMArtifacts(context.Background(), om, rows, defs)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 || stats.Public != 2 || stats.Classified != 1 || stats.Excluded != 1 || stats.Issuers != 1 {
		t.Fatalf("unexpected outputs: %v %+v", paths, stats)
	}
	var full lsm.Map
	var compact lsm.CompactMap
	var short []lsm.ShortDevice
	readLSMJSON(t, paths["logical_services_full"], &full)
	readLSMJSON(t, paths["logical_services_compact"], &compact)
	readLSMJSON(t, paths["logical_services_short"], &short)
	expanded, err := compact.Expand()
	if err != nil || !reflect.DeepEqual(full, expanded) {
		t.Fatalf("round trip mismatch: %v", err)
	}
	if !reflect.DeepEqual(full.Short(), short) {
		t.Fatal("short map differs from full observations")
	}
	if _, err := logicalservice.LoadDefinitions(paths["logical_services_definitions"]); err != nil {
		t.Fatalf("snapshot not reloadable: %v", err)
	}
	for _, path := range paths {
		if !strings.HasPrefix(filepath.Base(path), "stream-1-20261010-") {
			t.Fatalf("incorrect filename: %s", path)
		}
	}
	// Existing artifacts must not be overwritten; staging must be cleaned up.
	if _, _, err := writeLSMArtifacts(context.Background(), om, rows, defs); err == nil {
		t.Fatal("expected existing artifact error")
	}
	entries, _ := os.ReadDir(om.RunDir())
	if len(entries) != 5 {
		t.Fatalf("unexpected files after retry: %v", entries)
	}
	for _, mode := range []string{"cancel", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			_, d := lsmTestDefinitions(t)
			output, err := NewOutputManagerForRun("stream", t.TempDir(), now, now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			} else {
				duplicate := d.Rules[0]
				duplicate.ID = "competing_rule"
				d.Rules = append(d.Rules, duplicate)
			}
			if _, _, err := writeLSMArtifacts(ctx, output, rows, d); err == nil {
				t.Fatal("expected failure")
			}
			entries, err := os.ReadDir(output.RunDir())
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial artifacts: %v %v", entries, err)
			}
		})
	}
}

func TestDNSExtractLSMFinalStage(t *testing.T) {
	defsPath, _ := lsmTestDefinitions(t)
	input := t.TempDir()
	writeTimeNameDNSAndTCPPCAP(t, filepath.Join(input, "public.pcap"), "api.example.com", "8.8.8.8", 443)
	writeTimeNameDNSAndTCPPCAP(t, filepath.Join(input, "private.pcap"), "internal.example.com", "10.0.0.2", 1883)
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.245.214.104\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The same captures and inputs must retain their topology/direction outputs
	// whether the optional final mapping stage is enabled or disabled.
	baseline := map[string][]byte{}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			output := t.TempDir()
			opts := DefaultDNSExtractOptions()
			opts.ReadDir, opts.OutputRoot, opts.NetID = input, output, "test"
			opts.Fleet = fleetPath
			opts.DNSIPFile, opts.DisableSNI = "", true
			if enabled {
				opts.LogicalServices = defsPath
			}
			if err := runDNSExtract(&cobra.Command{}, nil, opts); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(output, "test", "pcap-date-*", "run-*", "_run-artifacts.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("manifest missing: %v %v", files, err)
			}
			var manifest RunArtifactsManifest
			readLSMJSON(t, files[0], &manifest)
			for _, key := range []string{"network_topology_matrix_json", "network_topology_matrix_compact", "service_endpoints", privateNonFleetEndpointsKey, flowDirectionCorrectionSQLKey} {
				data, err := os.ReadFile(manifest.Files[key])
				if err != nil {
					t.Fatalf("read %s: %v", key, err)
				}
				if !enabled {
					baseline[key] = data
				} else if !bytes.Equal(data, baseline[key]) {
					t.Errorf("enabling LSM changed %s", key)
				}
			}
			if !enabled {
				if manifest.LogicalServices != nil || manifest.Files["logical_services_full"] != "" {
					t.Fatal("LSM generated without definitions")
				}
				raw, err := os.ReadFile(files[0])
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte(`"logical_services"`)) {
					t.Fatal("disabled LSM statistics must be omitted, not null")
				}
				return
			}
			if manifest.LogicalServices == nil || manifest.LogicalServices.Classified != 1 {
				t.Fatalf("unexpected manifest LSM stats: %+v", manifest.LogicalServices)
			}
			var full lsm.Map
			readLSMJSON(t, manifest.Files["logical_services_full"], &full)
			if len(full.Devices) != 1 || len(full.Devices[0].Services) != 1 || full.Devices[0].Services[0].ServiceID != "example_platform" {
				t.Fatalf("unexpected LSM: %+v", full)
			}
			if _, err := os.Stat(manifest.Files["network_topology_matrix_json"]); err != nil {
				t.Fatalf("NTM missing: %v", err)
			}
			for _, key := range []string{"logical_services_definitions", "logical_services_compact", "logical_services_short", "logical_services_summary"} {
				if _, err := os.Stat(manifest.Files[key]); err != nil {
					t.Fatalf("%s missing: %v", key, err)
				}
			}
		})
	}
}

func TestDNSExtractLSMConflictDoesNotPublishManifest(t *testing.T) {
	path, defs := lsmTestDefinitions(t)
	duplicate := defs.Rules[0]
	duplicate.ID = "conflicting_rule"
	defs.Rules = append(defs.Rules, duplicate)
	data, err := yaml.Marshal(defs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	input, output := t.TempDir(), t.TempDir()
	writeTimeNameDNSAndTCPPCAP(t, filepath.Join(input, "capture.pcap"), "api.example.com", "8.8.8.8", 443)
	opts := DefaultDNSExtractOptions()
	opts.ReadDir, opts.OutputRoot, opts.NetID = input, output, "test"
	opts.DisableSNI, opts.LogicalServices = true, path
	err = runDNSExtract(&cobra.Command{}, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "classification conflicts") {
		t.Fatalf("expected classification conflict, got %v", err)
	}
	// Earlier reports can exist, but no success manifest or partial LSM may be published.
	reports, err := filepath.Glob(filepath.Join(output, "test", "pcap-date-*", "run-*", "network-topology-matrix.json"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("expected earlier NTM report: %v %v", reports, err)
	}
	entries, err := os.ReadDir(filepath.Dir(reports[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "_run-artifacts.json" || strings.Contains(name, "logical-services") || strings.Contains(name, "device-services") || strings.HasPrefix(name, ".lsm-") {
			t.Errorf("failure published %s", name)
		}
	}
}

func TestDNSExtractRejectsUnreadableDefinitionsBeforeCaptureWork(t *testing.T) {
	for _, kind := range []string{"missing", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			if kind == "missing" {
				path = filepath.Join(path, "missing.yaml")
			}
			opts := DefaultDNSExtractOptions()
			opts.ReadDir = filepath.Join(t.TempDir(), "missing-captures")
			opts.OutputRoot, opts.NetID, opts.LogicalServices = t.TempDir(), "test", path
			err := runDNSExtract(&cobra.Command{}, nil, opts)
			if err == nil || !strings.Contains(err.Error(), "load --logical-services") {
				t.Fatalf("expected early definitions failure, got %v", err)
			}
			entries, err := os.ReadDir(opts.OutputRoot)
			if err != nil || len(entries) != 0 {
				t.Fatalf("outputs created for unreadable definitions: %v %v", entries, err)
			}
		})
	}
}

func TestDNSExtractRejectsDefinitionsBeforeCaptureWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nunexpected: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := DefaultDNSExtractOptions()
	opts.ReadDir = filepath.Join(t.TempDir(), "missing-captures")
	opts.OutputRoot, opts.NetID, opts.LogicalServices = t.TempDir(), "test", path
	err := runDNSExtract(&cobra.Command{}, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "load --logical-services") {
		t.Fatalf("expected early definitions failure, got %v", err)
	}
	entries, err := os.ReadDir(opts.OutputRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outputs created for invalid definitions: %v %v", entries, err)
	}
}
