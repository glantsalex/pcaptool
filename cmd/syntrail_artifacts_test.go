package cmd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
)

var _ func(context.Context, *OutputManager, []string, string) (map[string]string, error) = runSYNTrailSidecar

func TestRunSYNTrailSidecarEmptyFleetPathReturnsNoArtifactsAndWritesNoFiles(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)

	artifacts, err := runSYNTrailSidecar(context.Background(), om, []string{filepath.Join(t.TempDir(), "missing.pcap")}, "")
	if err != nil {
		t.Fatalf("runSYNTrailSidecar() error = %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("len(runSYNTrailSidecar() artifacts) = %d, want 0", len(artifacts))
	}

	entries, err := os.ReadDir(om.RunDir())
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("runSYNTrailSidecar() wrote %d files with empty fleet path, want 0", len(entries))
	}
}

func TestWriteSYNTrailArtifactsWritesAllFilesManifestKeysAndBucketRows(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)
	ts := time.Date(2024, 3, 5, 12, 0, 0, 123_000_000, time.UTC)

	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecord("10.0.0.1", "203.0.113.10", 443, ts),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.11", 53, ts.Add(-time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecord("10.0.0.1", "192.168.1.20", 8443, ts.Add(time.Second)),
			testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.21", 5353, ts, syntrail.ProtocolUDP),
		},
		syntrail.BucketFleetToFleet: {
			testSYNTrailRecordWithProtocol("10.0.0.1", "10.0.0.2", 9443, ts.Add(2*time.Second), ""),
			testSYNTrailRecordWithProtocol("10.0.0.1", "10.0.0.3", 53, ts.Add(time.Second), syntrail.ProtocolUDP),
		},
		syntrail.BucketPrivateNonFleetToFleet: {
			testSYNTrailRecord("192.168.1.10", "10.0.0.2", 22, ts.Add(3*time.Second)),
			testSYNTrailRecordWithProtocol("192.168.1.11", "10.0.0.2", 53, ts.Add(2*time.Second), syntrail.ProtocolUDP),
		},
	}

	artifacts, err := writeSYNTrailArtifacts(om, buckets)
	if err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	if len(artifacts) != len(expectedSYNTrailArtifacts) {
		t.Fatalf("len(writeSYNTrailArtifacts() artifacts) = %d, want %d", len(artifacts), len(expectedSYNTrailArtifacts))
	}

	for _, artifact := range expectedSYNTrailArtifacts {
		wantPath := om.Path(artifact.filename)
		if got := artifacts[artifact.key]; got != wantPath {
			t.Fatalf("artifact %q path = %q, want %q", artifact.key, got, wantPath)
		}
		if _, err := os.Stat(wantPath); err != nil {
			t.Fatalf("stat %s: %v", artifact.filename, err)
		}
	}

	assertSYNTrailFile(t, om, "fleet-to-public-trail.csv", ""+
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n"+
		"10.0.0.1,203.0.113.10,443,tcp,2024-03-05 12:00:00.123\n"+
		"10.0.0.1,203.0.113.11,53,udp,2024-03-05 11:59:59.123\n")
	assertSYNTrailFile(t, om, "fleet-to-private-nonfleet-trail.csv", ""+
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n"+
		"10.0.0.1,192.168.1.20,8443,tcp,2024-03-05 12:00:01.123\n"+
		"10.0.0.1,192.168.1.21,5353,udp,2024-03-05 12:00:00.123\n")
	assertSYNTrailFile(t, om, "fleet-to-public-syn-unique.csv", ""+
		"src_ip,dst_ip,dst_port,protocol\n"+
		"10.0.0.1,203.0.113.10,443,tcp\n")
	assertSYNTrailFile(t, om, "fleet-to-private-nonfleet-syn-unique.csv", ""+
		"src_ip,dst_ip,dst_port,protocol\n"+
		"10.0.0.1,192.168.1.20,8443,tcp\n")
	assertSYNTrailFile(t, om, "private-servers-syn-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"192.168.1.20,8443,tcp\n")
	assertSYNTrailFile(t, om, "fleet-to-fleet-tcp-syn-trail.csv", ""+
		"src_ip,dst_ip,dst_port,syn_timestamp_utc\n"+
		"10.0.0.1,10.0.0.2,9443,2024-03-05 12:00:02.123\n")
	assertSYNTrailFile(t, om, "fleet-to-fleet-tcp-syn-unique.csv", ""+
		"src_ip,dst_ip,dst_port\n"+
		"10.0.0.1,10.0.0.2,9443\n")
	assertSYNTrailFile(t, om, "private-nonfleet-to-fleet-trail.csv", ""+
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n"+
		"192.168.1.10,10.0.0.2,22,tcp,2024-03-05 12:00:03.123\n"+
		"192.168.1.11,10.0.0.2,53,udp,2024-03-05 12:00:02.123\n")
	assertSYNTrailFile(t, om, "private-nonfleet-to-fleet-tcp-syn-unique.csv", ""+
		"src_ip,dst_ip,dst_port\n"+
		"192.168.1.10,10.0.0.2,22\n")
	assertSYNTrailFile(t, om, "private-probes-syn-unique.csv", ""+
		"src_ip,dst_port,protocol\n"+
		"192.168.1.10,22,tcp\n")

	if _, ok := artifacts["fleet_tcp_syn_trail"]; ok {
		t.Fatalf("artifacts contains removed key fleet_tcp_syn_trail")
	}
	if _, ok := artifacts["fleet_tcp_syn_unique"]; ok {
		t.Fatalf("artifacts contains removed key fleet_tcp_syn_unique")
	}
	if _, err := os.Stat(om.Path("fleet-tcp-syn-trail.csv")); !os.IsNotExist(err) {
		t.Fatalf("fleet-tcp-syn-trail.csv stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(om.Path("fleet-tcp-syn-unique.csv")); !os.IsNotExist(err) {
		t.Fatalf("fleet-tcp-syn-unique.csv stat error = %v, want not exist", err)
	}

	oldArtifacts := []expectedSYNTrailArtifact{
		{filename: "fleet-to-public-syn-trail.csv", key: "fleet_to_public_syn_trail"},
		{filename: "fleet-to-private-nonfleet-syn-trail.csv", key: "fleet_to_private_nonfleet_syn_trail"},
		{filename: "private-nonfleet-to-fleet-tcp-syn-trail.csv", key: "private_nonfleet_to_fleet_tcp_syn_trail"},
	}
	for _, artifact := range oldArtifacts {
		if _, ok := artifacts[artifact.key]; ok {
			t.Fatalf("artifacts contains old key %q", artifact.key)
		}
		if _, err := os.Stat(om.Path(artifact.filename)); !os.IsNotExist(err) {
			t.Fatalf("%s stat error = %v, want not exist", artifact.filename, err)
		}
	}
}

func TestWriteSYNTrailArtifactsEmptyBucketsWriteHeaderOnlyFiles(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)

	artifacts, err := writeSYNTrailArtifacts(om, nil)
	if err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}
	if len(artifacts) != len(expectedSYNTrailArtifacts) {
		t.Fatalf("len(writeSYNTrailArtifacts() artifacts) = %d, want %d", len(artifacts), len(expectedSYNTrailArtifacts))
	}

	for _, artifact := range expectedSYNTrailArtifacts {
		assertSYNTrailFile(t, om, artifact.filename, artifact.header)
		if got := artifacts[artifact.key]; got != om.Path(artifact.filename) {
			t.Fatalf("artifact %q path = %q, want %q", artifact.key, got, om.Path(artifact.filename))
		}
	}
}

type expectedSYNTrailArtifact struct {
	filename string
	key      string
	header   string
}

var expectedSYNTrailArtifacts = []expectedSYNTrailArtifact{
	{
		filename: "fleet-to-public-trail.csv",
		key:      "fleet_to_public_trail",
		header:   "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
	},
	{
		filename: "fleet-to-private-nonfleet-trail.csv",
		key:      "fleet_to_private_nonfleet_trail",
		header:   "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
	},
	{
		filename: "fleet-to-public-syn-unique.csv",
		key:      "fleet_to_public_syn_unique",
		header:   "src_ip,dst_ip,dst_port,protocol\n",
	},
	{
		filename: "fleet-to-private-nonfleet-syn-unique.csv",
		key:      "fleet_to_private_nonfleet_syn_unique",
		header:   "src_ip,dst_ip,dst_port,protocol\n",
	},
	{
		filename: "private-servers-syn-unique.csv",
		key:      "private_servers_syn_unique",
		header:   "dst_ip,dst_port,protocol\n",
	},
	{
		filename: "fleet-to-fleet-tcp-syn-trail.csv",
		key:      "fleet_to_fleet_tcp_syn_trail",
		header:   "src_ip,dst_ip,dst_port,syn_timestamp_utc\n",
	},
	{
		filename: "fleet-to-fleet-tcp-syn-unique.csv",
		key:      "fleet_to_fleet_tcp_syn_unique",
		header:   "src_ip,dst_ip,dst_port\n",
	},
	{
		filename: "private-nonfleet-to-fleet-trail.csv",
		key:      "private_nonfleet_to_fleet_trail",
		header:   "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
	},
	{
		filename: "private-nonfleet-to-fleet-tcp-syn-unique.csv",
		key:      "private_nonfleet_to_fleet_tcp_syn_unique",
		header:   "src_ip,dst_ip,dst_port\n",
	},
	{
		filename: "private-probes-syn-unique.csv",
		key:      "private_probes_syn_unique",
		header:   "src_ip,dst_port,protocol\n",
	},
}

func newSYNTrailTestOutputManager(t *testing.T) *OutputManager {
	t.Helper()

	om, err := NewOutputManager("net", t.TempDir())
	if err != nil {
		t.Fatalf("NewOutputManager: %v", err)
	}
	return om
}

func assertSYNTrailFile(t *testing.T, om *OutputManager, filename, want string) {
	t.Helper()

	got, err := os.ReadFile(om.Path(filename))
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", filename, string(got), want)
	}
}

func testSYNTrailRecord(src, dst string, dstPort uint16, timestamp time.Time) syntrail.Record {
	return testSYNTrailRecordWithProtocol(src, dst, dstPort, timestamp, syntrail.ProtocolTCP)
}

func testSYNTrailRecordWithProtocol(src, dst string, dstPort uint16, timestamp time.Time, protocol syntrail.Protocol) syntrail.Record {
	return syntrail.Record{
		SrcIP:     netip.MustParseAddr(src),
		DstIP:     netip.MustParseAddr(dst),
		DstPort:   dstPort,
		Protocol:  protocol,
		Timestamp: timestamp,
	}
}
