package cmd

import (
	"context"
	"fmt"
	"io"
	"net/netip"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/aglants/pcaptool/internal/syntrail"
)

type synTrailArtifactOptions struct {
	FTPControlPorts              map[uint16]struct{}
	FTPPassiveMinPort            uint16
	ServerSummaryExcludeUDPPorts map[uint16]struct{}
	ScanOptions                  syntrail.ScanOptions
	Debug                        bool
}

var scanSYNTrailFilesWithOptions = syntrail.ScanFilesWithOptions

func runSYNTrailSidecar(
	ctx context.Context,
	om *OutputManager,
	files []string,
	fleet *syntrail.FleetSet,
	opt synTrailArtifactOptions,
) (map[string]string, error) {
	if fleet == nil {
		return nil, nil
	}

	records, err := scanSYNTrailFilesWithOptions(ctx, files, opt.ScanOptions)
	if err != nil {
		return nil, fmt.Errorf("scan SYN trail packet captures: %w", err)
	}
	if opt.ScanOptions.Progress != nil {
		opt.ScanOptions.Progress(len(files), len(files), "")
	}

	artifacts, err := writeSYNTrailArtifacts(om, syntrail.ClassifyRecords(records, *fleet), opt)
	if err != nil {
		return nil, fmt.Errorf("write SYN trail artifacts: %w", err)
	}
	return artifacts, nil
}

func writeSYNTrailArtifacts(
	om *OutputManager,
	buckets syntrail.BucketedRecords,
	opt synTrailArtifactOptions,
) (map[string]string, error) {
	artifacts := make(map[string]string, len(synTrailArtifactSpecs)+2)
	_, privateServerRecords := syntrail.SplitFleetToNonFleetByDestinationLocality(
		bucketRecords(buckets, syntrail.BucketFleetToNonFleet),
	)
	privateServerRecords = filterPassiveFTPServerSummaryRecords(privateServerRecords, opt)
	privateServerRecords = filterUDPServerSummaryRecords(privateServerRecords, opt.ServerSummaryExcludeUDPPorts)
	privateProbeRecords := tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet))

	for _, spec := range synTrailArtifactSpecs {
		if spec.debugOnly && !opt.Debug {
			continue
		}
		records := spec.records(buckets)
		switch spec.key {
		case "public_servers_unique":
			records = filterPassiveFTPServerSummaryRecords(records, opt)
			records = filterUDPServerSummaryRecords(records, opt.ServerSummaryExcludeUDPPorts)
		}
		path, err := writeSYNTrailArtifact(om, spec.filename, records, spec.writer)
		if err != nil {
			return nil, err
		}
		artifacts[spec.key] = path
	}

	path, err := writePrivateNonFleetEndpointsArtifact(om, privateServerRecords, privateProbeRecords)
	if err != nil {
		return nil, err
	}
	artifacts[privateNonFleetEndpointsKey] = path

	path, err = writeFlowDirectionCorrectionSQL(om, syntrail.PrivateServerTuples(privateServerRecords))
	if err != nil {
		return nil, err
	}
	artifacts[flowDirectionCorrectionSQLKey] = path

	return artifacts, nil
}

type synTrailArtifactSpec struct {
	filename  string
	key       string
	debugOnly bool
	records   func(syntrail.BucketedRecords) []syntrail.Record
	writer    func(io.Writer, []syntrail.Record) error
}

var synTrailArtifactSpecs = []synTrailArtifactSpec{
	{
		filename:  "fleet-to-public-trail.csv",
		key:       "fleet_to_public_trail",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			public, _ := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return public
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename:  "fleet-to-private-nonfleet-trail.csv",
		key:       "fleet_to_private_nonfleet_trail",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			_, privateNonFleet := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return privateNonFleet
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename:  "fleet-to-public-unique.csv",
		key:       "fleet_to_public_unique",
		debugOnly: true,
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
		filename:  "fleet-to-private-nonfleet-syn-unique.csv",
		key:       "fleet_to_private_nonfleet_syn_unique",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			_, privateNonFleet := syntrail.SplitFleetToNonFleetByDestinationLocality(bucketRecords(buckets, syntrail.BucketFleetToNonFleet))
			return tcpSYNTrailRecords(privateNonFleet)
		},
		writer: syntrail.WriteTCPUniqueCSV,
	},
	{
		filename:  "fleet-to-fleet-tcp-syn-trail.csv",
		key:       "fleet_to_fleet_tcp_syn_trail",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketFleetToFleet))
		},
		writer: syntrail.WriteTrailCSV,
	},
	{
		filename:  "fleet-to-fleet-tcp-syn-unique.csv",
		key:       "fleet_to_fleet_tcp_syn_unique",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketFleetToFleet))
		},
		writer: syntrail.WriteUniqueCSV,
	},
	{
		filename:  "private-nonfleet-to-fleet-trail.csv",
		key:       "private_nonfleet_to_fleet_trail",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet)
		},
		writer: syntrail.WriteProtocolTrailCSV,
	},
	{
		filename:  "private-nonfleet-to-fleet-tcp-syn-unique.csv",
		key:       "private_nonfleet_to_fleet_tcp_syn_unique",
		debugOnly: true,
		records: func(buckets syntrail.BucketedRecords) []syntrail.Record {
			return tcpSYNTrailRecords(bucketRecords(buckets, syntrail.BucketPrivateNonFleetToFleet))
		},
		writer: syntrail.WriteUniqueCSV,
	},
}

const (
	privateNonFleetEndpointsFilename = "private-nonfleet-endpoints.json"
	privateNonFleetEndpointsKey      = "private_nonfleet_endpoints"
)

func bucketRecords(buckets syntrail.BucketedRecords, bucket syntrail.Bucket) []syntrail.Record {
	// Borrow a read-only view. Selectors that feed an in-place sorting writer
	// must first produce owned storage (for example, tcpSYNTrailRecords).
	// Locality splitting and the other writers do not mutate this view.
	return buckets[bucket]
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

type synTrailPair struct {
	srcIP netip.Addr
	dstIP netip.Addr
}

func filterPassiveFTPServerSummaryRecords(
	records []syntrail.Record,
	opt synTrailArtifactOptions,
) []syntrail.Record {
	opt = normalizeSYNTrailArtifactOptions(opt)

	controlSeen := make(map[synTrailPair]struct{})
	for _, record := range records {
		if !isTCPSYNTrailRecord(record) {
			continue
		}
		if _, ok := opt.FTPControlPorts[record.DstPort]; !ok {
			continue
		}
		controlSeen[synTrailPair{srcIP: record.SrcIP, dstIP: record.DstIP}] = struct{}{}
	}

	filtered := make([]syntrail.Record, 0, len(records))
	for _, record := range records {
		if shouldSuppressPassiveFTPRecord(record, opt, controlSeen) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func normalizeSYNTrailArtifactOptions(opt synTrailArtifactOptions) synTrailArtifactOptions {
	defaults := connectivity.DefaultOptions()
	if opt.FTPControlPorts == nil {
		opt.FTPControlPorts = defaults.FTPControlPorts
	}
	if opt.FTPPassiveMinPort == 0 {
		opt.FTPPassiveMinPort = defaults.FTPPassiveMinPort
	}
	return opt
}

func shouldSuppressPassiveFTPRecord(
	record syntrail.Record,
	opt synTrailArtifactOptions,
	controlSeen map[synTrailPair]struct{},
) bool {
	if !isTCPSYNTrailRecord(record) || record.DstPort < opt.FTPPassiveMinPort {
		return false
	}
	if _, ok := opt.FTPControlPorts[record.DstPort]; ok {
		return false
	}
	_, ok := controlSeen[synTrailPair{srcIP: record.SrcIP, dstIP: record.DstIP}]
	return ok
}

func isTCPSYNTrailRecord(record syntrail.Record) bool {
	return record.Protocol == "" || record.Protocol == syntrail.ProtocolTCP
}

func filterUDPServerSummaryRecords(
	records []syntrail.Record,
	excludedPorts map[uint16]struct{},
) []syntrail.Record {
	if len(excludedPorts) == 0 {
		return records
	}

	filtered := make([]syntrail.Record, 0, len(records))
	for _, record := range records {
		if record.Protocol == syntrail.ProtocolUDP {
			if _, excluded := excludedPorts[record.DstPort]; excluded {
				continue
			}
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

func writePrivateNonFleetEndpointsArtifact(
	om *OutputManager,
	serverRecords []syntrail.Record,
	probeRecords []syntrail.Record,
) (string, error) {
	f, err := om.Create(privateNonFleetEndpointsFilename)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", privateNonFleetEndpointsFilename, err)
	}

	path := f.Name()
	writeErr := syntrail.WritePrivateNonFleetEndpointsJSON(f, serverRecords, probeRecords)
	closeErr := f.Close()
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", privateNonFleetEndpointsFilename, writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", privateNonFleetEndpointsFilename, closeErr)
	}
	return path, nil
}
