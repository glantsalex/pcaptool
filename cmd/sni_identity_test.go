package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A middle owner must survive even when a later owner has >128 observations
// of the same IP/endpoint tuple. Duplicate files must not change that result.
func TestSNITimedIdentityPipeline(t *testing.T) {
	capture, err := os.ReadFile("testdata/radius-subnets.pcap")
	if err != nil {
		t.Fatal(err)
	}
	inputs := t.TempDir()
	for _, name := range []string{"b.pcap", "a.pcap"} {
		if err := os.WriteFile(filepath.Join(inputs, name), capture, 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	var reference []map[string]any
	for _, mode := range []struct{ procs, fleetWorkers int }{{1, 0}, {2, 0}, {8, 2}} {
		runtime.GOMAXPROCS(mode.procs)
		opts := DefaultDNSExtractOptions()
		opts.ReadDir, opts.OutputRoot, opts.NetID = inputs, t.TempDir(), "identity-test"
		opts.RadiusIMSI = true
		opts.FleetSubnets = []string{"10.181.0.0/16"}
		opts.DisableSNI = false
		opts.FleetScanWorkers = mode.fleetWorkers
		opts.Format = "json"
		if err := runDNSExtract(&cobra.Command{}, nil, opts); err != nil {
			t.Fatal(err)
		}
		paths, err := filepath.Glob(filepath.Join(opts.OutputRoot, "identity-test", "*", "*", "network-topology-matrix.json"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("paths=%v err=%v", paths, err)
		}
		raw, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, row := range doc.Entries {
			if row["dns_name"] == "reused.example.test" && strings.Contains(row["dns_source"].(string), "sni") {
				got[row["issuer_ip"].(string)]++
			}
		}
		want := map[string]int{"323456789012345": 1, "423456789012345": 1, "523456789012345": 1}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mode=%+v SNI owners=%v, want %v", mode, got, want)
		}
		if reference == nil {
			reference = doc.Entries
		} else if !reflect.DeepEqual(reference, doc.Entries) {
			t.Fatalf("mode=%+v changed topology", mode)
		}
	}
}
