package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestDNSExtractPrivateNonFleetSnapshotTime(t *testing.T) {
	first := time.Date(2026, 10, 2, 15, 30, 45, 123000000, time.UTC)
	for _, workers := range []int{0, 1} {
		for _, emptyFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("workers_%d/empty_first_%t", workers, emptyFirst), func(t *testing.T) {
				readDir := t.TempDir()
				var firstPackets []timestampedPacket
				if !emptyFirst {
					firstPackets = []timestampedPacket{
						// The raw first packet counts even though neither endpoint is fleet.
						{ts: first, data: buildTCPPacket(t, "192.168.1.1", "192.168.1.2", 41000, 443, true, false)},
						{ts: first.Add(-24 * time.Hour), data: buildTCPPacket(t, "10.0.0.1", "192.168.1.2", 41001, 443, true, false)},
					}
				}
				writePacketsToPCAP(t, filepath.Join(readDir, "a.pcap"), firstPackets)
				laterFileTime := first.Add(-48 * time.Hour)
				writePacketsToPCAP(t, filepath.Join(readDir, "b.pcap"), []timestampedPacket{
					{ts: laterFileTime, data: buildTCPPacket(t, "10.0.0.1", "192.168.1.2", 41002, 443, true, false)},
					{ts: laterFileTime.Add(time.Millisecond), data: buildTCPPacket(t, "192.168.1.2", "10.0.0.1", 443, 41002, true, true)},
				})
				fleetPath := filepath.Join(t.TempDir(), "fleet.txt")
				if err := os.WriteFile(fleetPath, []byte("10.0.0.1\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				opts := DefaultDNSExtractOptions()
				opts.ReadDir = readDir
				opts.OutputRoot = t.TempDir()
				opts.NetID = "snapshot-test"
				opts.Fleet = fleetPath
				opts.FleetScanWorkers = workers
				opts.DisableSNI = true
				if err := executeDNSExtract(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				runDir := findSingleRunDir(t, opts.OutputRoot, opts.NetID)
				manifest := readRunArtifactsManifest(t, runDir)
				data, err := os.ReadFile(manifest.Files[privateNonFleetEndpointsKey])
				if err != nil {
					t.Fatal(err)
				}
				var document syntrail.PrivateNonFleetEndpointsDocument
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				want := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).UnixMilli()
				if emptyFirst {
					want = 0
				}
				if document.SchemaVersion != 1 || document.SnapshotTime != want {
					t.Fatalf("schema/snapshot = %d/%d, want 1/%d", document.SchemaVersion, document.SnapshotTime, want)
				}
				if len(document.Endpoints) != 1 || document.Endpoints[0].IP != "192.168.1.2" || len(document.Endpoints[0].Server.Listeners) != 1 || document.Endpoints[0].Server.Listeners[0].FleetDevicesCount != 1 {
					t.Fatalf("endpoint aggregation changed: %+v", document.Endpoints)
				}
				if manifest.PCAPDate != "2026-09-30" || manifest.FirstPacketTSUTC != laterFileTime.Format(time.RFC3339Nano) {
					t.Fatalf("existing run chronology changed: %+v", manifest)
				}
			})
		}
	}
}
