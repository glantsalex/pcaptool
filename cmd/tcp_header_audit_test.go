package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestInvalidTCPHeadersExcludedAndAuditedOnce(t *testing.T) {
	const device, good, bad = "10.0.0.1", "198.51.100.10", "198.51.100.11"
	const tcpStart = 14 + 20 // test builder uses Ethernet and IPv4 without options
	base := time.Unix(1_700_000_000, 0).UTC()
	zeroOffset := buildTCPPacket(t, device, bad, 40000, 256, false, false)
	zeroOffset[tcpStart+12] = 0
	// A malformed option can leave both the decoded ports and the TLS payload
	// populated. It must not donate its SNI name to another edge.
	payload := append([]byte{2, 1, 0, 0}, buildTLSClientHelloPayload("invalid.example")...)
	badSNI := buildTCPPacketWithPayload(t, device, good, 40000, 256, true, false, payload)
	badSNI[tcpStart+12] = 6 << 4
	readDir := t.TempDir()
	nested := filepath.Join(readDir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	writePacketsToPCAP(t, filepath.Join(readDir, "traffic.pcap"), []timestampedPacket{
		{base, zeroOffset},
		{base.Add(time.Second), buildTCPPacket(t, device, good, 40000, 256, true, false)},
		{base.Add(2 * time.Second), buildTCPPacket(t, good, device, 256, 40000, true, true)},
	})
	writePacketsToPCAP(t, filepath.Join(nested, "traffic.pcap"), []timestampedPacket{
		{base.Add(3 * time.Second), badSNI}, {base.Add(4 * time.Second), zeroOffset},
	})
	records, err := syntrail.ScanFile(context.Background(), filepath.Join(nested, "traffic.pcap"), nil)
	if err != nil || len(records) != 0 {
		t.Fatalf("fleet scan of malformed packets: records=%v error=%v", records, err)
	}
	for _, mode := range []struct {
		name    string
		workers int
	}{{"shared", 0}, {"separate", 2}} {
		t.Run(mode.name, func(t *testing.T) {
			opts := DefaultDNSExtractOptions()
			opts.ReadDir, opts.OutputRoot, opts.NetID = readDir, t.TempDir(), "tcp-audit"
			opts.FleetSubnets = []string{"10.0.0.0/24"}
			opts.FleetScanWorkers = mode.workers
			if err := executeDNSExtract(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			run := findSingleRunDir(t, opts.OutputRoot, opts.NetID)
			manifest := readRunArtifactsManifest(t, run)
			wantFiles := map[string]uint64{"traffic.pcap": 1, "nested/traffic.pcap": 2}
			if manifest.PacketAudit.IgnoredInvalidTCPHeaders != 3 || !reflect.DeepEqual(manifest.PacketAudit.InvalidTCPHeadersByFile, wantFiles) {
				t.Fatalf("unexpected audit: %+v", manifest.PacketAudit)
			}
			data, err := os.ReadFile(filepath.Join(run, "network-topology-matrix.json"))
			if err != nil {
				t.Fatal(err)
			}
			var matrix struct {
				Entries []struct {
					Destination string `json:"destination_ip"`
					Name        string `json:"dns_name"`
					Port        uint16 `json:"port"`
				}
			}
			if err := json.Unmarshal(data, &matrix); err != nil {
				t.Fatal(err)
			}
			if len(matrix.Entries) != 1 || matrix.Entries[0].Destination != good || matrix.Entries[0].Port != 256 || matrix.Entries[0].Name != "" {
				t.Fatalf("unexpected topology: %s", data)
			}
		})
	}
}
