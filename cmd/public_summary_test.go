package cmd

import (
	"bytes"
	"github.com/aglants/pcaptool/internal/syntrail"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func TestPublicSummaryMatchesMaterializedPipeline(t *testing.T) {
	base := []syntrail.Record{
		testSYNTrailRecord("10.0.0.1", "8.8.8.8", 30000, time.Time{}),
		testSYNTrailRecord("10.0.0.2", "8.8.8.8", 30000, time.Time{}),
		testSYNTrailRecord("10.0.0.1", "8.8.8.8", 21, time.Time{}),
		testSYNTrailRecord("10.0.0.1", "192.168.1.1", 443, time.Time{}),
		testSYNTrailRecord("10.0.0.1", "169.254.1.1", 443, time.Time{}),
		testSYNTrailRecordWithProtocol("10.0.0.1", "8.8.8.8", 30000, time.Time{}, syntrail.ProtocolUDP),
		testSYNTrailRecordWithProtocol("10.0.0.1", "8.8.8.8", 53, time.Time{}, syntrail.ProtocolUDP),
		testSYNTrailRecordWithProtocol("10.0.0.2", "8.8.8.8", 443, time.Time{}, 0),
		testSYNTrailRecord("10.0.0.2", "8.8.8.8", 443, time.Time{}),
	}
	opts := []synTrailArtifactOptions{{}, {FTPControlPorts: map[uint16]struct{}{}, ServerSummaryExcludeUDPPorts: map[uint16]struct{}{53: {}}}, {FTPControlPorts: map[uint16]struct{}{443: {}}, FTPPassiveMinPort: 100}}
	for _, opt := range opts {
		for seed := int64(0); seed < 20; seed++ {
			records := append([]syntrail.Record{}, base...)
			records = append(records, base...)
			if seed > 0 {
				rand.New(rand.NewSource(seed)).Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
			}
			before := append([]syntrail.Record{}, records...)
			expected := syntrail.SelectFleetToNonFleetByDestinationLocality(records, false)
			expected = filterOwnedPassiveFTPServerSummaryRecords(expected, opt)
			expected = filterOwnedUDPServerSummaryRecords(expected, opt.ServerSummaryExcludeUDPPorts)
			got := publicServerSummaryRecords(records, opt)
			var wantCSV, gotCSV bytes.Buffer
			if err := syntrail.WritePublicServersCSV(&wantCSV, expected); err != nil {
				t.Fatal(err)
			}
			if err := syntrail.WritePublicServersCSV(&gotCSV, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wantCSV.Bytes(), gotCSV.Bytes()) {
				t.Fatalf("seed %d: CSV differs", seed)
			}
			if !reflect.DeepEqual(before, records) {
				t.Fatal("mutated borrowed records")
			}
			if len(got) != len(syntrail.PrivateServerTuples(expected)) {
				t.Fatal("summary retained duplicate observations")
			}
		}
	}
	if got := publicServerSummaryRecords(nil, synTrailArtifactOptions{}); len(got) != 0 {
		t.Fatal(got)
	}
}

func BenchmarkPublicSummarySelection(b *testing.B) {
	records := make([]syntrail.Record, 100000)
	for i := range records {
		records[i] = testSYNTrailRecord("10.0.0.1", "8.8.8.8", uint16(80+i%8), time.Time{})
	}
	for _, direct := range []bool{false, true} {
		name := "materialized"
		if direct {
			name = "direct"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var selected []syntrail.Record
				if direct {
					selected = publicServerSummaryRecords(records, synTrailArtifactOptions{})
				} else {
					selected = syntrail.SelectFleetToNonFleetByDestinationLocality(records, false)
					selected = filterOwnedPassiveFTPServerSummaryRecords(selected, synTrailArtifactOptions{})
				}
				if len(syntrail.PrivateServerTuples(selected)) != 8 {
					b.Fatal("wrong endpoints")
				}
			}
		})
	}
}
