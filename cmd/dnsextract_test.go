package cmd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/spf13/cobra"
)

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
