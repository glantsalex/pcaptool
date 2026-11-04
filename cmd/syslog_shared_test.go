package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectionSyslogSharedScanMatchesSidecar(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprint(seeded), func(t *testing.T) {
			dir := t.TempDir()
			fleet := filepath.Join(t.TempDir(), "fleet.txt")
			if err := os.WriteFile(fleet, []byte("10.0.0.1\n10.0.0.2\n"), 0600); err != nil {
				t.Fatal(err)
			}
			early := []byte("truncated body without a recognizable header")
			later := []byte("<140>1 2026-10-10T00:00:00Z host app - - - message")
			registry := ""
			if seeded {
				later = early
				registry = filepath.Join(t.TempDir(), "registry.json")
				if err := os.WriteFile(registry, []byte(`{"schema_version":1,"account_id":"account","stream_id":"syslog-merge","endpoints":[{"ip":"10.4.100.58","server":{"listeners":[{"protocol":"udp","port":6514,"evidence":"syslog","first_seen":"2026-10-01","last_seen":"2026-10-01"}]}}]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
			writePacketsToPCAP(t, filepath.Join(dir, "first.pcap"), []timestampedPacket{{ts: at, data: buildUDPPacketWithPayload(t, "10.0.0.1", "10.4.100.58", 45000, 6514, early)}})
			writePacketsToPCAP(t, filepath.Join(dir, "second.pcap"), []timestampedPacket{{ts: at.Add(time.Second), data: buildUDPPacketWithPayload(t, "10.0.0.2", "10.4.100.58", 45001, 6514, later)}})
			var referenceJSON, referenceSQL []byte
			for _, workers := range []int{0, 1, 4} {
				opts := DefaultDNSExtractOptions()
				opts.ReadDir = dir
				opts.NetID = "syslog-merge"
				opts.OutputRoot = t.TempDir()
				opts.Fleet = fleet
				opts.FleetScanWorkers = workers
				opts.DirectionRegistry = registry
				opts.DisableSNI = true
				// Fleet evidence must survive connection-layer transport suppression.
				opts.OnlyTCP = true
				if err := executeDNSExtract(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				run := findSingleRunDir(t, opts.OutputRoot, opts.NetID)
				data, err := os.ReadFile(filepath.Join(run, privateNonFleetEndpointsFilename))
				if err != nil {
					t.Fatal(err)
				}
				sql, err := os.ReadFile(filepath.Join(run, flowDirectionCorrectionSQLFilename))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), `"fleet_devices_count": 2`) || !strings.Contains(string(data), `"evidence": "syslog"`) {
					t.Fatalf("workers=%d missing qualified senders: %s", workers, data)
				}
				if !strings.Contains(string(sql), "AND src_port IN (6514)") {
					t.Fatal("missing learned syslog SQL")
				}
				if workers == 0 {
					referenceJSON = data
					referenceSQL = sql
				} else if !bytes.Equal(data, referenceJSON) || !bytes.Equal(sql, referenceSQL) {
					t.Fatalf("workers=%d differs from shared scan", workers)
				}
			}
		})
	}
}
