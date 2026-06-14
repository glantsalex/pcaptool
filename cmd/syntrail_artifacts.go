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
		records := append([]syntrail.Record(nil), buckets[spec.bucket]...)
		path, err := writeSYNTrailArtifact(om, spec.filename, records, spec.writer)
		if err != nil {
			return nil, err
		}
		artifacts[spec.key] = path
	}

	return artifacts, nil
}

type synTrailArtifactSpec struct {
	bucket   syntrail.Bucket
	filename string
	key      string
	writer   func(io.Writer, []syntrail.Record) error
}

var synTrailArtifactSpecs = []synTrailArtifactSpec{
	{
		bucket:   syntrail.BucketFleetToNonFleet,
		filename: "fleet-tcp-syn-trail.csv",
		key:      "fleet_tcp_syn_trail",
		writer:   syntrail.WriteTrailCSV,
	},
	{
		bucket:   syntrail.BucketFleetToNonFleet,
		filename: "fleet-tcp-syn-unique.csv",
		key:      "fleet_tcp_syn_unique",
		writer:   syntrail.WriteUniqueCSV,
	},
	{
		bucket:   syntrail.BucketFleetToFleet,
		filename: "fleet-to-fleet-tcp-syn-trail.csv",
		key:      "fleet_to_fleet_tcp_syn_trail",
		writer:   syntrail.WriteTrailCSV,
	},
	{
		bucket:   syntrail.BucketFleetToFleet,
		filename: "fleet-to-fleet-tcp-syn-unique.csv",
		key:      "fleet_to_fleet_tcp_syn_unique",
		writer:   syntrail.WriteUniqueCSV,
	},
	{
		bucket:   syntrail.BucketPrivateNonFleetToFleet,
		filename: "private-nonfleet-to-fleet-tcp-syn-trail.csv",
		key:      "private_nonfleet_to_fleet_tcp_syn_trail",
		writer:   syntrail.WriteTrailCSV,
	},
	{
		bucket:   syntrail.BucketPrivateNonFleetToFleet,
		filename: "private-nonfleet-to-fleet-tcp-syn-unique.csv",
		key:      "private_nonfleet_to_fleet_tcp_syn_unique",
		writer:   syntrail.WriteUniqueCSV,
	},
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
