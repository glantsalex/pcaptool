package cmd

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
)

var _ func(context.Context, *OutputManager, []string, string, synTrailArtifactOptions) (map[string]string, error) = runSYNTrailSidecar

func TestRunSYNTrailSidecarEmptyFleetPathReturnsNoArtifactsAndWritesNoFiles(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)

	artifacts, err := runSYNTrailSidecar(
		context.Background(),
		om,
		[]string{filepath.Join(t.TempDir(), "missing.pcap")},
		"",
		synTrailArtifactOptions{},
	)
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
	om := newSYNTrailTestOutputManagerForNet(t, "404163-1")
	ts := time.Date(2024, 3, 5, 12, 0, 0, 123_000_000, time.UTC)

	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecord("10.0.0.1", "203.0.113.10", 443, ts),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.11", 53, ts.Add(-time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecord("10.0.0.1", "192.168.1.20", 8443, ts.Add(time.Second)),
			testSYNTrailRecordWithProtocol("10.0.0.1", "10.4.0.230", 53, ts, syntrail.ProtocolUDP),
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

	artifacts, err := writeSYNTrailArtifacts(om, buckets, synTrailArtifactOptions{Debug: true})
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
		"10.0.0.1,10.4.0.230,53,udp,2024-03-05 12:00:00.123\n")
	assertSYNTrailFile(t, om, "fleet-to-public-unique.csv", ""+
		"src_ip,dst_ip,dst_port,protocol\n"+
		"10.0.0.1,203.0.113.10,443,tcp\n"+
		"10.0.0.1,203.0.113.11,53,udp\n")
	assertSYNTrailFile(t, om, "public-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"203.0.113.10,443,tcp\n"+
		"203.0.113.11,53,udp\n")
	assertSYNTrailFile(t, om, "fleet-to-private-nonfleet-syn-unique.csv", ""+
		"src_ip,dst_ip,dst_port,protocol\n"+
		"10.0.0.1,192.168.1.20,8443,tcp\n")
	assertSYNTrailFile(t, om, "private-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"192.168.1.20,8443,tcp\n"+
		"10.4.0.230,53,udp\n")
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
	assertSYNTrailFile(t, om, "private-probes-unique.csv", ""+
		"src_ip,dst_port,protocol\n"+
		"192.168.1.10,22,tcp\n")

	assertFlowDirectionCorrectionSQL(t, om, []string{
		"`{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-404163-1`",
		"`{{gcp_project_id}}.{{bq_dataset}}.flow-data-404163-1`",
		"WHEN (NOT src_is_private) AND dst_is_private",
		"THEN 'public_to_private_artifact'",
		"AND protocol_lc = 'tcp'\n       AND src_ip = '192.168.1.20'\n       AND src_port = 8443",
		"THEN 'private_server_192_168_1_20_8443_tcp_seen_as_src_artifact'",
		"AND protocol_lc = 'udp'\n       AND src_ip = '10.4.0.230'\n       AND src_port = 53",
		"THEN 'private_server_10_4_0_230_53_udp_seen_as_src_artifact'",
		"END AS swap_reason",
	}, []string{
		"AS swap_reason\nFROM decide",
	})
	sql := readSYNTrailFile(t, om, flowDirectionCorrectionSQLFilename)
	assertSubstringOrder(t, sql, "THEN 'public_to_private_artifact'", "private_server_192_168_1_20_8443_tcp_seen_as_src_artifact")
	assertSubstringOrder(t, sql, "private_server_192_168_1_20_8443_tcp_seen_as_src_artifact", "private_server_10_4_0_230_53_udp_seen_as_src_artifact")
	finalSelectIdx := strings.LastIndex(sql, "\nSELECT\n")
	if finalSelectIdx == -1 {
		t.Fatalf("flow direction SQL missing final SELECT: %q", sql)
	}
	finalSelect := sql[finalSelectIdx:]
	if !strings.Contains(finalSelect, "IF(swap_reason IS NOT NULL") {
		t.Fatalf("final SELECT does not use swap_reason for correction: %q", finalSelect)
	}
	if strings.Contains(finalSelect, "AS swap_reason") {
		t.Fatalf("final SELECT projects swap_reason: %q", finalSelect)
	}

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
	if _, ok := artifacts["fleet_to_public_syn_unique"]; ok {
		t.Fatal("artifacts contains old key fleet_to_public_syn_unique")
	}
	if _, err := os.Stat(om.Path("fleet-to-public-syn-unique.csv")); !os.IsNotExist(err) {
		t.Fatalf("fleet-to-public-syn-unique.csv stat error = %v, want not exist", err)
	}
	if _, ok := artifacts["private_servers_syn_unique"]; ok {
		t.Fatal("artifacts contains old key private_servers_syn_unique")
	}
	if _, err := os.Stat(om.Path("private-servers-syn-unique.csv")); !os.IsNotExist(err) {
		t.Fatalf("private-servers-syn-unique.csv stat error = %v, want not exist", err)
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
	if _, ok := artifacts["private_probes_syn_unique"]; ok {
		t.Fatal("artifacts contains old key private_probes_syn_unique")
	}
	if _, err := os.Stat(om.Path("private-probes-syn-unique.csv")); !os.IsNotExist(err) {
		t.Fatalf("private-probes-syn-unique.csv stat error = %v, want not exist", err)
	}
}

func TestWriteSYNTrailArtifactsNonDebugWritesOnlyAlwaysOnFiles(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)

	artifacts, err := writeSYNTrailArtifacts(om, nil, synTrailArtifactOptions{Debug: false})
	if err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	for _, artifact := range expectedSYNTrailArtifacts {
		_, present := artifacts[artifact.key]
		_, statErr := os.Stat(om.Path(artifact.filename))
		if artifact.debugOnly {
			if present {
				t.Fatalf("non-debug artifacts contains debug-only key %q", artifact.key)
			}
			if !os.IsNotExist(statErr) {
				t.Fatalf("non-debug %s stat error = %v, want not exist", artifact.filename, statErr)
			}
			continue
		}
		if !present {
			t.Fatalf("non-debug artifacts missing always-on key %q", artifact.key)
		}
		if statErr != nil {
			t.Fatalf("stat always-on %s: %v", artifact.filename, statErr)
		}
	}
	if len(artifacts) != 4 {
		t.Fatalf("non-debug artifact count = %d, want 4", len(artifacts))
	}
	if got := artifacts["private_probes_unique"]; got != om.Path("private-probes-unique.csv") {
		t.Fatalf("private probes artifact path = %q", got)
	}
	if _, ok := artifacts["private_probes_syn_unique"]; ok {
		t.Fatal("non-debug artifacts contains old key private_probes_syn_unique")
	}
	if _, err := os.Stat(om.Path("private-probes-syn-unique.csv")); !os.IsNotExist(err) {
		t.Fatalf("private-probes-syn-unique.csv stat error = %v, want not exist", err)
	}
}

func TestWriteSYNTrailArtifactsFlowDirectionSQLDedupesDuplicatePrivateServerTuples(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecordWithProtocol("10.0.0.1", "10.4.0.230", 53, ts, syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.2", "10.4.0.230", 53, ts.Add(time.Second), syntrail.ProtocolUDP),
		},
	}

	if _, err := writeSYNTrailArtifacts(om, buckets, synTrailArtifactOptions{}); err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	sql := readSYNTrailFile(t, om, flowDirectionCorrectionSQLFilename)
	if got := strings.Count(sql, "private_server_10_4_0_230_53_udp_seen_as_src_artifact"); got != 1 {
		t.Fatalf("duplicate private server SQL rule count = %d, want 1", got)
	}
}

func TestWriteSYNTrailArtifactsEmptyBucketsWriteHeaderOnlyFiles(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)

	artifacts, err := writeSYNTrailArtifacts(om, nil, synTrailArtifactOptions{Debug: true})
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

	sql := readSYNTrailFile(t, om, flowDirectionCorrectionSQLFilename)
	if strings.Count(sql, "public_to_private_artifact") != 1 {
		t.Fatalf("empty-bucket SQL public_to_private_artifact count = %d, want 1", strings.Count(sql, "public_to_private_artifact"))
	}
	if strings.Contains(sql, "private_server_") {
		t.Fatalf("empty-bucket SQL contains private server rule: %q", sql)
	}
}

func TestFilterPassiveFTPServerSummaryRecords(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	control := testSYNTrailRecord("10.0.0.1", "192.168.1.20", 21, ts)
	passive := testSYNTrailRecord("10.0.0.1", "192.168.1.20", 30000, ts.Add(time.Second))

	tests := []struct {
		name    string
		records []syntrail.Record
		opt     synTrailArtifactOptions
		want    []syntrail.Record
	}{
		{
			name:    "same pair TCP passive port is suppressed with defaults",
			records: []syntrail.Record{passive, control},
			want:    []syntrail.Record{control},
		},
		{
			name:    "same pair empty protocol passive port is suppressed",
			records: []syntrail.Record{control, testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.20", 30001, ts, "")},
			want:    []syntrail.Record{control},
		},
		{
			name:    "passive port without control is retained",
			records: []syntrail.Record{passive},
			want:    []syntrail.Record{passive},
		},
		{
			name: "control on different source does not suppress",
			records: []syntrail.Record{
				control,
				testSYNTrailRecord("10.0.0.2", "192.168.1.20", 30000, ts),
			},
			want: []syntrail.Record{
				control,
				testSYNTrailRecord("10.0.0.2", "192.168.1.20", 30000, ts),
			},
		},
		{
			name: "port below passive minimum is retained",
			records: []syntrail.Record{
				control,
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 29999, ts),
			},
			want: []syntrail.Record{
				control,
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 29999, ts),
			},
		},
		{
			name: "UDP is retained",
			records: []syntrail.Record{
				control,
				testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.20", 30000, ts, syntrail.ProtocolUDP),
			},
			want: []syntrail.Record{
				control,
				testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.20", 30000, ts, syntrail.ProtocolUDP),
			},
		},
		{
			name: "retained records preserve input order",
			records: []syntrail.Record{
				testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.20", 31000, ts, syntrail.ProtocolUDP),
				passive,
				control,
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 29999, ts),
			},
			want: []syntrail.Record{
				testSYNTrailRecordWithProtocol("10.0.0.1", "192.168.1.20", 31000, ts, syntrail.ProtocolUDP),
				control,
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 29999, ts),
			},
		},
		{
			name: "configured control port is retained above passive minimum",
			records: []syntrail.Record{
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 21000, ts),
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 22000, ts),
			},
			opt: synTrailArtifactOptions{
				FTPControlPorts:   map[uint16]struct{}{21000: {}},
				FTPPassiveMinPort: 20000,
			},
			want: []syntrail.Record{
				testSYNTrailRecord("10.0.0.1", "192.168.1.20", 21000, ts),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]syntrail.Record(nil), tt.records...)

			got := filterPassiveFTPServerSummaryRecords(tt.records, tt.opt)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filterPassiveFTPServerSummaryRecords() = %+v, want %+v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.records, original) {
				t.Fatalf("filterPassiveFTPServerSummaryRecords() mutated input: got %+v, want %+v", tt.records, original)
			}
		})
	}
}

func TestFilterUDPServerSummaryRecords(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	udpExcluded := testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33434, ts, syntrail.ProtocolUDP)
	udpRetained := testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33535, ts, syntrail.ProtocolUDP)
	tcpSamePort := testSYNTrailRecord("10.0.0.1", "203.0.113.10", 33434, ts)
	emptyProtocolSamePort := testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33435, ts, "")

	tests := []struct {
		name     string
		records  []syntrail.Record
		excluded map[uint16]struct{}
		want     []syntrail.Record
	}{
		{
			name:     "explicit UDP destination port is suppressed",
			records:  []syntrail.Record{udpRetained, udpExcluded, tcpSamePort, emptyProtocolSamePort},
			excluded: map[uint16]struct{}{33434: {}, 33435: {}},
			want:     []syntrail.Record{udpRetained, tcpSamePort, emptyProtocolSamePort},
		},
		{
			name:     "empty set disables suppression",
			records:  []syntrail.Record{udpExcluded, udpRetained},
			excluded: map[uint16]struct{}{},
			want:     []syntrail.Record{udpExcluded, udpRetained},
		},
		{
			name:     "nil set disables suppression",
			records:  []syntrail.Record{udpExcluded},
			excluded: nil,
			want:     []syntrail.Record{udpExcluded},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]syntrail.Record(nil), tt.records...)

			got := filterUDPServerSummaryRecords(tt.records, tt.excluded)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filterUDPServerSummaryRecords() = %+v, want %+v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.records, original) {
				t.Fatalf("filterUDPServerSummaryRecords() mutated input: got %+v, want %+v", tt.records, original)
			}
		})
	}
}

func TestWriteSYNTrailArtifactsFiltersPassiveFTPOnlyFromServerSummaries(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecord("10.0.0.1", "203.0.113.10", 21000, ts),
			testSYNTrailRecord("10.0.0.1", "203.0.113.10", 40000, ts.Add(time.Second)),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 41000, ts.Add(2*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecord("10.0.0.2", "192.168.1.20", 21000, ts),
			testSYNTrailRecord("10.0.0.2", "192.168.1.20", 17736, ts.Add(time.Second)),
			testSYNTrailRecord("10.0.0.2", "192.168.1.20", 17845, ts.Add(2*time.Second)),
			testSYNTrailRecordWithProtocol("10.0.0.2", "192.168.1.20", 17900, ts.Add(3*time.Second), syntrail.ProtocolUDP),
		},
	}
	original := append([]syntrail.Record(nil), buckets[syntrail.BucketFleetToNonFleet]...)
	opt := synTrailArtifactOptions{
		FTPControlPorts:   map[uint16]struct{}{21000: {}},
		FTPPassiveMinPort: 17000,
		Debug:             true,
	}

	if _, err := writeSYNTrailArtifacts(om, buckets, opt); err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	assertSYNTrailFile(t, om, "public-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"203.0.113.10,21000,tcp\n"+
		"203.0.113.10,41000,udp\n")
	assertSYNTrailFile(t, om, "private-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"192.168.1.20,21000,tcp\n"+
		"192.168.1.20,17900,udp\n")
	assertFlowDirectionCorrectionSQL(t, om, []string{
		"AND protocol_lc = 'tcp'\n       AND src_ip = '192.168.1.20'\n       AND src_port = 21000",
		"AND protocol_lc = 'udp'\n       AND src_ip = '192.168.1.20'\n       AND src_port = 17900",
	}, []string{
		"src_port = 17736",
		"src_port = 17845",
		"src_port = 40000",
	})

	assertSYNTrailFileContains(t, om, "fleet-to-public-trail.csv", "10.0.0.1,203.0.113.10,40000,tcp")
	assertSYNTrailFileContains(t, om, "fleet-to-public-unique.csv", "10.0.0.1,203.0.113.10,40000,tcp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-trail.csv", "10.0.0.2,192.168.1.20,17736,tcp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-trail.csv", "10.0.0.2,192.168.1.20,17845,tcp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-trail.csv", "10.0.0.2,192.168.1.20,17900,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-syn-unique.csv", "10.0.0.2,192.168.1.20,17736,tcp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-syn-unique.csv", "10.0.0.2,192.168.1.20,17845,tcp")

	if !reflect.DeepEqual(buckets[syntrail.BucketFleetToNonFleet], original) {
		t.Fatalf("writeSYNTrailArtifacts() mutated bucket records: got %+v, want %+v", buckets[syntrail.BucketFleetToNonFleet], original)
	}
}

func TestWriteSYNTrailArtifactsExcludesUDPPortsOnlyFromServerSummaries(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33433, ts, syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33434, ts.Add(time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33534, ts.Add(2*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33535, ts.Add(3*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecord("10.0.0.1", "203.0.113.10", 33434, ts.Add(4*time.Second)),
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33534, ts.Add(5*time.Second), ""),
			testSYNTrailRecordWithProtocol("10.0.0.2", "192.168.1.20", 33433, ts.Add(6*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.2", "192.168.1.20", 33434, ts.Add(7*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.2", "192.168.1.20", 33534, ts.Add(8*time.Second), syntrail.ProtocolUDP),
			testSYNTrailRecordWithProtocol("10.0.0.2", "192.168.1.20", 33535, ts.Add(9*time.Second), syntrail.ProtocolUDP),
		},
	}
	original := append([]syntrail.Record(nil), buckets[syntrail.BucketFleetToNonFleet]...)
	excludedPorts, err := parseOptionalPortRangeSet("33434-33534")
	if err != nil {
		t.Fatalf("parse default UDP exclusion range: %v", err)
	}
	opt := synTrailArtifactOptions{
		ServerSummaryExcludeUDPPorts: excludedPorts,
		Debug:                        true,
	}

	if _, err := writeSYNTrailArtifacts(om, buckets, opt); err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	assertSYNTrailFile(t, om, "public-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"203.0.113.10,33434,tcp\n"+
		"203.0.113.10,33534,tcp\n"+
		"203.0.113.10,33433,udp\n"+
		"203.0.113.10,33535,udp\n")
	assertSYNTrailFile(t, om, "private-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"192.168.1.20,33433,udp\n"+
		"192.168.1.20,33535,udp\n")
	assertFlowDirectionCorrectionSQL(t, om, []string{
		"AND protocol_lc = 'udp'\n       AND src_ip = '192.168.1.20'\n       AND src_port = 33433",
		"AND protocol_lc = 'udp'\n       AND src_ip = '192.168.1.20'\n       AND src_port = 33535",
	}, []string{
		"src_port = 33434",
		"src_port = 33534",
	})

	assertSYNTrailFileContains(t, om, "fleet-to-public-trail.csv", "10.0.0.1,203.0.113.10,33434,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-public-trail.csv", "10.0.0.1,203.0.113.10,33534,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-public-unique.csv", "10.0.0.1,203.0.113.10,33434,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-public-unique.csv", "10.0.0.1,203.0.113.10,33534,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-trail.csv", "10.0.0.2,192.168.1.20,33434,udp")
	assertSYNTrailFileContains(t, om, "fleet-to-private-nonfleet-trail.csv", "10.0.0.2,192.168.1.20,33534,udp")
	assertSYNTrailFile(t, om, "fleet-to-private-nonfleet-syn-unique.csv", "src_ip,dst_ip,dst_port,protocol\n")

	if !reflect.DeepEqual(buckets[syntrail.BucketFleetToNonFleet], original) {
		t.Fatalf("writeSYNTrailArtifacts() mutated bucket records: got %+v, want %+v", buckets[syntrail.BucketFleetToNonFleet], original)
	}
}

func TestWriteSYNTrailArtifactsEmptyUDPExclusionSetRetainsServerSummaryUDP(t *testing.T) {
	om := newSYNTrailTestOutputManager(t)
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	buckets := syntrail.BucketedRecords{
		syntrail.BucketFleetToNonFleet: {
			testSYNTrailRecordWithProtocol("10.0.0.1", "203.0.113.10", 33434, ts, syntrail.ProtocolUDP),
		},
	}

	if _, err := writeSYNTrailArtifacts(om, buckets, synTrailArtifactOptions{
		ServerSummaryExcludeUDPPorts: map[uint16]struct{}{},
	}); err != nil {
		t.Fatalf("writeSYNTrailArtifacts() error = %v", err)
	}

	assertSYNTrailFile(t, om, "public-servers-unique.csv", ""+
		"dst_ip,dst_port,protocol\n"+
		"203.0.113.10,33434,udp\n")
}

type expectedSYNTrailArtifact struct {
	filename  string
	key       string
	header    string
	debugOnly bool
}

var expectedSYNTrailArtifacts = []expectedSYNTrailArtifact{
	{
		filename:  "fleet-to-public-trail.csv",
		key:       "fleet_to_public_trail",
		header:    "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
		debugOnly: true,
	},
	{
		filename:  "fleet-to-private-nonfleet-trail.csv",
		key:       "fleet_to_private_nonfleet_trail",
		header:    "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
		debugOnly: true,
	},
	{
		filename:  "fleet-to-public-unique.csv",
		key:       "fleet_to_public_unique",
		header:    "src_ip,dst_ip,dst_port,protocol\n",
		debugOnly: true,
	},
	{
		filename: "public-servers-unique.csv",
		key:      "public_servers_unique",
		header:   "dst_ip,dst_port,protocol\n",
	},
	{
		filename:  "fleet-to-private-nonfleet-syn-unique.csv",
		key:       "fleet_to_private_nonfleet_syn_unique",
		header:    "src_ip,dst_ip,dst_port,protocol\n",
		debugOnly: true,
	},
	{
		filename: "private-servers-unique.csv",
		key:      "private_servers_unique",
		header:   "dst_ip,dst_port,protocol\n",
	},
	{
		filename:  "fleet-to-fleet-tcp-syn-trail.csv",
		key:       "fleet_to_fleet_tcp_syn_trail",
		header:    "src_ip,dst_ip,dst_port,syn_timestamp_utc\n",
		debugOnly: true,
	},
	{
		filename:  "fleet-to-fleet-tcp-syn-unique.csv",
		key:       "fleet_to_fleet_tcp_syn_unique",
		header:    "src_ip,dst_ip,dst_port\n",
		debugOnly: true,
	},
	{
		filename:  "private-nonfleet-to-fleet-trail.csv",
		key:       "private_nonfleet_to_fleet_trail",
		header:    "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n",
		debugOnly: true,
	},
	{
		filename:  "private-nonfleet-to-fleet-tcp-syn-unique.csv",
		key:       "private_nonfleet_to_fleet_tcp_syn_unique",
		header:    "src_ip,dst_ip,dst_port\n",
		debugOnly: true,
	},
	{
		filename: "private-probes-unique.csv",
		key:      "private_probes_unique",
		header:   "src_ip,dst_port,protocol\n",
	},
	{
		filename: flowDirectionCorrectionSQLFilename,
		key:      flowDirectionCorrectionSQLKey,
		header:   flowDirectionCorrectionSQL("net", nil),
	},
}

func newSYNTrailTestOutputManager(t *testing.T) *OutputManager {
	t.Helper()
	return newSYNTrailTestOutputManagerForNet(t, "net")
}

func newSYNTrailTestOutputManagerForNet(t *testing.T, netID string) *OutputManager {
	t.Helper()

	om, err := NewOutputManager(netID, t.TempDir())
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

func assertSYNTrailFileContains(t *testing.T, om *OutputManager, filename, want string) {
	t.Helper()

	got := readSYNTrailFile(t, om, filename)
	if !strings.Contains(string(got), want) {
		t.Fatalf("%s = %q, want substring %q", filename, string(got), want)
	}
}

func assertFlowDirectionCorrectionSQL(t *testing.T, om *OutputManager, wantContains []string, wantAbsent []string) {
	t.Helper()

	got := readSYNTrailFile(t, om, flowDirectionCorrectionSQLFilename)
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Fatalf("%s = %q, want substring %q", flowDirectionCorrectionSQLFilename, got, want)
		}
	}
	for _, unwanted := range wantAbsent {
		if strings.Contains(got, unwanted) {
			t.Fatalf("%s = %q, unwanted substring %q", flowDirectionCorrectionSQLFilename, got, unwanted)
		}
	}
}

func assertSubstringOrder(t *testing.T, got, before, after string) {
	t.Helper()

	beforeIdx := strings.Index(got, before)
	if beforeIdx == -1 {
		t.Fatalf("missing expected substring %q in %q", before, got)
	}
	afterIdx := strings.Index(got, after)
	if afterIdx == -1 {
		t.Fatalf("missing expected substring %q in %q", after, got)
	}
	if beforeIdx >= afterIdx {
		t.Fatalf("substring %q appears at %d, want before %q at %d", before, beforeIdx, after, afterIdx)
	}
}

func readSYNTrailFile(t *testing.T, om *OutputManager, filename string) string {
	t.Helper()

	got, err := os.ReadFile(om.Path(filename))
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	return string(got)
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
