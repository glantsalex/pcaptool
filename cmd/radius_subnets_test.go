package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/spf13/cobra"
)

func TestRadiusSubnetPipelineSharedAndSeparateScans(t *testing.T) {
	capture, err := os.ReadFile("testdata/radius-subnets.pcap")
	if err != nil {
		t.Fatal(err)
	}
	inputs := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputs, "traffic.pcap"), capture, 0600); err != nil {
		t.Fatal(err)
	}
	var reference []byte
	for _, mode := range []struct {
		workers int
		exact   bool
	}{{0, false}, {1, false}, {2, false}, {0, true}, {2, true}} {
		workers := mode.workers
		opts := DefaultDNSExtractOptions()
		opts.ReadDir = inputs
		opts.OutputRoot = t.TempDir()
		opts.NetID = "radius-test"
		opts.RadiusIMSI = true
		opts.FleetSubnets = []string{"10.181.0.0/16"}
		if mode.exact {
			opts.FleetSubnets = nil
			opts.Fleet = filepath.Join(t.TempDir(), "fleet.txt")
			if err := os.WriteFile(opts.Fleet, []byte("10.181.1.1\n10.181.1.10\n10.181.1.11\n10.181.1.12\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		opts.FleetScanWorkers = workers
		opts.Format = "json"
		if err := runDNSExtract(&cobra.Command{}, nil, opts); err != nil {
			t.Fatal(err)
		}
		paths, err := filepath.Glob(filepath.Join(opts.OutputRoot, "radius-test", "*", "*", "private-nonfleet-endpoints.json"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("paths=%v err=%v", paths, err)
		}
		raw, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if reference == nil {
			reference = raw
		} else if !bytes.Equal(reference, raw) {
			t.Fatalf("scan mode %d changed artifact", workers)
		}
		var doc syntrail.PrivateNonFleetEndpointsDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.FleetIdentityBasis != "imsi" {
			t.Fatalf("missing identity basis: %s", raw)
		}
		endpoints := map[string]syntrail.PrivateNonFleetEndpoint{}
		for _, e := range doc.Endpoints {
			endpoints[e.IP] = e
		}
		if _, ok := endpoints["10.250.0.99"]; ok {
			t.Fatalf("RADIUS server admitted as device traffic: %s", raw)
		}
		for _, ip := range []string{"10.250.0.5", "10.250.0.6"} {
			list := endpoints[ip].Server.Listeners
			if len(list) != 1 || list[0].FleetDevicesCount != 2 {
				t.Fatalf("incorrect IMSI count for %s: %s", ip, raw)
			}
		}
		if endpoints["10.250.0.5"].Server.Listeners[0].UnresolvedFleetIPsCount != 0 {
			t.Fatalf("retained unresolved fleet observations: %s", raw)
		}
		if len(endpoints["10.250.0.7"].Probe.Targets) != 1 || endpoints["10.250.0.7"].Probe.Targets[0].FleetDevicesCount != 1 {
			t.Fatalf("probe not attributed: %s", raw)
		}
		if len(endpoints["10.250.0.8"].Server.Listeners) != 1 || endpoints["10.250.0.8"].Server.Listeners[0].FleetDevicesCount != 1 {
			t.Fatalf("active session did not reach capture end: %s", raw)
		}
		run := filepath.Dir(paths[0])
		matrix, err := os.ReadFile(filepath.Join(run, "network-topology-matrix.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(matrix), "device.example.test") || !strings.Contains(string(matrix), "123456789012345") || strings.Contains(string(matrix), "excluded.example.test") {
			t.Fatalf("SNI/identity/admission failed: %s", matrix)
		}
		if strings.Contains(string(matrix), "10.250.0.99") {
			t.Fatalf("RADIUS leaked into topology: %s", matrix)
		}
		sql, err := os.ReadFile(filepath.Join(run, "flow-direction-correction.sql"))
		if err != nil || !strings.Contains(string(sql), "10.250.0.5") || !strings.Contains(string(sql), "10.250.0.6") {
			t.Fatalf("SQL missing discoveries: %s %v", sql, err)
		}
	}
}
