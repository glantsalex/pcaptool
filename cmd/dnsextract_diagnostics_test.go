package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/diagnostics"
)

// Exercise both the cloud/default shared scan and the explicit sidecar. Compare
// every artifact byte except the manifest's inherently run-specific paths/time.
func TestDNSExtractDiagnosticsPreserveArtifacts(t *testing.T) {
	input := t.TempDir()
	writeFleetMemoryFixture(t, input, 3, 3)
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n10.0.0.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{0, 2} {
		for _, debug := range []bool{false, true} {
			run := func(enabled bool) map[string]string {
				root := ""
				if enabled {
					root = t.TempDir()
				}
				t.Setenv(diagnostics.Environment, root)
				opts := DefaultDNSExtractOptions()
				opts.ReadDir = input
				opts.OutputRoot = t.TempDir()
				opts.NetID = "diagnostic-fixture"
				opts.Fleet = fleetPath
				opts.FleetScanWorkers = workers
				opts.DisableSNI = true
				opts.Debug = debug
				if err := executeDNSExtract(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				runDir := findSingleRunDir(t, opts.OutputRoot, opts.NetID)
				entries, err := os.ReadDir(runDir)
				if err != nil {
					t.Fatal(err)
				}
				contents := map[string]string{}
				for _, entry := range entries {
					if entry.IsDir() {
						t.Fatalf("unexpected directory %s", entry.Name())
					}
					data, err := os.ReadFile(filepath.Join(runDir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if entry.Name() == "_run-artifacts.json" {
						contents[entry.Name()] = "run-specific metadata"
						continue
					}
					contents[entry.Name()] = string(data)
				}
				if enabled {
					logs, err := filepath.Glob(filepath.Join(root, "run-*", "memory.jsonl"))
					if err != nil || len(logs) != 1 {
						t.Fatalf("diagnostic logs: %v %v", logs, err)
					}
					data, err := os.ReadFile(logs[0])
					if err != nil {
						t.Fatal(err)
					}
					for _, stage := range []string{"dns_scan_complete", "connection_scan_complete", "fleet_classify", "fleet_write_public_servers_unique", "fleet_write_private_endpoints", "fleet_artifacts_complete", "run_completed"} {
						if !strings.Contains(string(data), `"stage":"`+stage+`"`) {
							t.Errorf("missing stage %s", stage)
						}
					}
				}
				return contents
			}
			before, after := run(false), run(true)
			if !reflect.DeepEqual(before, after) {
				for name, expected := range before {
					if after[name] != expected {
						t.Errorf("workers=%d debug=%v artifact %s changed", workers, debug, name)
					}
				}
				if len(before) != len(after) {
					t.Error("artifact count changed")
				}
			}
		}
	}
}

func TestDNSExtractDiagnosticsRecordsFailedRun(t *testing.T) {
	root := t.TempDir()
	t.Setenv(diagnostics.Environment, root)
	opts := DefaultDNSExtractOptions()
	opts.NetID = "diagnostic-fixture"
	opts.ReadDir = filepath.Join(t.TempDir(), "does-not-exist")
	if err := executeDNSExtract(context.Background(), opts); err == nil {
		t.Fatal("expected invalid input error")
	}
	logs, err := filepath.Glob(filepath.Join(root, "run-*", "memory.jsonl"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs: %v %v", logs, err)
	}
	data, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"stage":"run_failed"`) {
		t.Fatal("missing failure marker")
	}
}
