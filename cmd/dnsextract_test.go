package cmd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/spf13/cobra"
)

func TestDnsextractFleetScanWorkersDefaultIsOne(t *testing.T) {
	cmd := dnsextractCommandForTest(t)
	flag := cmd.Flags().Lookup("fleet-scan-workers")
	if flag == nil {
		t.Fatal("dnsextract missing --fleet-scan-workers flag")
	}
	if flag.DefValue != "1" {
		t.Fatalf("--fleet-scan-workers default = %q, want 1", flag.DefValue)
	}
}

func TestDnsextractFleetScanWorkersValidationRejectsZero(t *testing.T) {
	if err := validateFleetScanWorkers("fleet.txt", 0); err == nil {
		t.Fatal("validateFleetScanWorkers() error = nil, want error")
	}
}

func TestDnsextractFleetScanWorkersValidationRejectsNegative(t *testing.T) {
	if err := validateFleetScanWorkers("fleet.txt", -2); err == nil {
		t.Fatal("validateFleetScanWorkers() error = nil, want error")
	}
}

func TestDnsextractFleetScanWorkersIgnoredWithoutFleet(t *testing.T) {
	if err := validateFleetScanWorkers("", 0); err != nil {
		t.Fatalf("validateFleetScanWorkers() without fleet error = %v, want nil", err)
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
		gotFiles []string
		gotOpt   syntrail.ScanOptions
		called   bool
	)
	scanSYNTrailFilesWithOptions = func(ctx context.Context, files []string, opt syntrail.ScanOptions) ([]syntrail.Record, error) {
		called = true
		gotFiles = append([]string(nil), files...)
		gotOpt = opt
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

	artifacts, err := runSYNTrailSidecarForDNSExtract(
		context.Background(),
		newSYNTrailTestOutputManager(t),
		wantFiles,
		fleetPath,
		synTrailArtifactOptions{},
		syntrail.ScanOptions{Workers: 8},
	)
	if err != nil {
		t.Fatalf("runSYNTrailSidecarForDNSExtract() error = %v", err)
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
	if len(artifacts) == 0 {
		t.Fatal("runSYNTrailSidecarForDNSExtract() returned no artifacts")
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
