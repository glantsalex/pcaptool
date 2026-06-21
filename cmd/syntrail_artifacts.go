package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func runSYNTrailSidecar(ctx context.Context, om *OutputManager, files []string, fleetPath string) (map[string]string, error) {
	if fleetPath == "" {
		return nil, nil
	}

	fleet, err := syntrail.LoadFleetIPv4File(fleetPath)
	if err != nil {
		return nil, fmt.Errorf("load SYN trail fleet file: %w", err)
	}

	records, err := syntrail.ScanFiles(ctx, files)
	if err != nil {
		return nil, fmt.Errorf("scan SYN trail packet captures: %w", err)
	}

	artifacts, err := writeSYNTrailArtifacts(om, syntrail.ClassifyRecords(records, fleet))
	if err != nil {
		return nil, fmt.Errorf("write SYN trail artifacts: %w", err)
	}
	return artifacts, nil
}

func writeSYNTrailArtifacts(om *OutputManager, buckets syntrail.BucketedRecords) (map[string]string, error) {
	artifacts := make(map[string]string, len(synTrailArtifactSpecs))

	for _, spec := range synTrailArtifactSpecs {
		records := spec.records(buckets)
		path, err := writeSYNTrailArtifact(om, spec.filename, records, spec.writer)
		if err != nil {
			return nil, err
		}
		artifacts[spec.key] = path
	}

	return artifacts, nil
}

type synTrailArtifactSpec struct {
	filename string
	key      string
	records  func(syntrail.BucketedRecords) []syntrail.Record
	writer   func(io.Writer, []syntrail.Record) error
}

var synTrailArtifactSpecs = []synTrailArtifactSpec{
	{
		filename: "fleet-to-public-trail.csv",
		key:      "fleet_to_public_trail",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			public, _ := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return public
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename: "fleet-to-private-nonfleet-trail.csv",
		key:      "fleet_to_private_nonfleet_trail",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			_, privateNonFleet := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return privateNonFleet
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename: "fleet-to-public-unique.csv",
		key:      "fleet_to_public_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			public, _ := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return public
		},
		writer: syntrail.WriteProtocolUniqueCSV,
	},
	{
		filename: "public-servers-unique.csv",
		key:      "public_servers_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			public, _ := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return public
		},
		writer: syntrail.WritePublicServersCSV,
	},
	{
		filename: "fleet-to-private-nonfleet-syn-unique.csv",
		key:      "fleet_to_private_nonfleet_syn_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			_, privateNonFleet := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return tcpSYNTrailRecords(privateNonFleet)
		},
		writer: syntrail.WriteTCPUniqueCSV,
	},
	{
		filename: "private-servers-syn-unique.csv",
		key:      "private_servers_syn_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			_, privateNonFleet := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return tcpSYNTrailRecords(privateNonFleet)
		},
		writer: syntrail.WritePrivateServersCSV,
	},
	{
		filename: "fleet-to-fleet-tcp-syn-trail.csv",
		key:      "fleet_to_fleet_tcp_syn_trail",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketFleetToFleet))
		},
		writer: syntrail.WriteTrailCSV,
	},
	{
		filename: "fleet-to-fleet-tcp-syn-unique.csv",
		key:      "fleet_to_fleet_tcp_syn_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketFleetToFleet))
		},
		writer: syntrail.WriteUniqueCSV,
	},
	{
		filename: "private-nonfleet-to-fleet-trail.csv",
		key:      "private_nonfleet_to_fleet_trail",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet)
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename: "private-nonfleet-to-fleet-tcp-syn-unique.csv",
		key:      "private_nonfleet_to_fleet_tcp_syn_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet))
		},
		writer: syntrail.WriteUniqueCSV,
	},
	{
		filename: "private-probes-syn-unique.csv",
		key:      "private_probes_syn_unique",
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet))
		},
		writer: syntrail.WritePrivateProbesCSV,
	},
}

func bucketRecords(buckets syntrail.BucketedRecords, bucket syntrail.Bucket) []syntrail.Record {
	return append([]syntrail.Record(nil), buckets[bucket]...)
}

func tcpSYNTrailRecords(records []syntrail.Record) []syntrail.Record {
	filtered := make([]syntrail.Record, 0, len(records))
	for _, record := range records {
		if record.Protocol != "" && record.Protocol != syntrail.ProtocolTCP {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func writeSYNTrailArtifact(om *OutputManager, filename string, records []syntrail.Record, write func(io.Writer, []syntrail.Record) error) (string, error) {
	f, err := om.Create(filename)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", filename, err)
	}

	path := f.Name()
	writeErr := write(f, records)
	closeErr := f.Close()
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", filename, writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", filename, closeErr)
	}

	return path, nil
}
