package cmd

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestRecord48CompatibilityRereadRejectsTimestampBeforeOutput(t *testing.T) {
	readDir := t.TempDir()
	path := filepath.Join(readDir, "mixed-invalid-time.pcap")
	writeMixedInterfaceFleetPCAPNG(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The fourth EPB is the first Ethernet SYN after the incompatible raw-IP
	// interface. The shared reader invokes its strict reread before reaching it.
	packets := 0
	for offset := 0; offset < len(data); {
		length := int(binary.LittleEndian.Uint32(data[offset+4:]))
		if length < 12 || offset+length > len(data) {
			t.Fatal("invalid fixture block")
		}
		if binary.LittleEndian.Uint32(data[offset:]) == 6 {
			packets++
			if packets == 4 {
				nanos := uint64(math.MaxInt64) + 1
				binary.LittleEndian.PutUint32(data[offset+12:], uint32(nanos>>32))
				binary.LittleEndian.PutUint32(data[offset+16:], uint32(nanos))
			}
		}
		offset += length
	}
	if packets != 5 {
		t.Fatalf("fixture packet count = %d, want 5", packets)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	original := scanSYNTrailFile
	t.Cleanup(func() { scanSYNTrailFile = original })
	rereads := 0
	scanSYNTrailFile = func(ctx context.Context, path string, options syntrail.ScanOptions) ([]syntrail.Record, error) {
		rereads++
		return original(ctx, path, options)
	}
	opts := DefaultDNSExtractOptions()
	opts.ReadDir, opts.OutputRoot, opts.NetID = readDir, t.TempDir(), "record48-recovery-error"
	opts.Fleet, opts.FleetScanWorkers, opts.DisableSNI, opts.IgnoreNTP = fleetPath, 0, true, false
	err = executeDNSExtract(context.Background(), opts)
	if rereads != 1 || err == nil || !strings.Contains(err.Error(), "validate fleet evidence after connection read error") || !strings.Contains(err.Error(), "outside signed Unix nanosecond range") || !strings.Contains(err.Error(), path) {
		t.Fatalf("strict compatibility rereads=%d error=%v", rereads, err)
	}
	entries, err := os.ReadDir(opts.OutputRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("timestamp failure produced output: %v", entries)
	}
}
