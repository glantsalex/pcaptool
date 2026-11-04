package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aglants/pcaptool/internal/direction"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/aglants/pcaptool/internal/syntrail"
)

type synTrailArtifactOptions struct {
	DirectionRegistry            string
	FTPControlPorts              map[uint16]struct{}
	FTPPassiveMinPort            uint16
	ServerSummaryExcludeUDPPorts map[uint16]struct{}
	ScanOptions                  syntrail.ScanOptions
	Debug                        bool
	FirstFilePacketTimestamp     time.Time
}

var (
	scanSYNTrailFile             = syntrail.ScanFileWithOptions
	scanSYNTrailFilesWithOptions = syntrail.ScanFilesWithOptions
)

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

	var err error
	opt.ScanOptions, err = directionScanOptions(fleet, opt.DirectionRegistry, om.NetID(), opt.ScanOptions)
	if err != nil {
		return nil, err
	}
	records, err := scanSYNTrailFilesWithOptions(ctx, files, opt.ScanOptions)
	if err != nil {
		return nil, fmt.Errorf("scan SYN trail packet captures: %w", err)
	}
	if opt.ScanOptions.Progress != nil {
		opt.ScanOptions.Progress(len(files), len(files), "")
	}

	artifacts, err := writeSYNTrailArtifactsFromRecords(om, records, *fleet, opt)
	if err != nil {
		return nil, fmt.Errorf("write SYN trail artifacts: %w", err)
	}
	return artifacts, nil
}

func writeSYNTrailArtifactsFromRecords(
	om *OutputManager,
	records []syntrail.Record,
	fleet syntrail.FleetSet,
	opt synTrailArtifactOptions,
) (map[string]string, error) {
	return writeSYNTrailArtifacts(om, syntrail.ClassifyRecords(records, fleet), opt)
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

	path, err := writePrivateNonFleetEndpointsArtifact(om, privateServerRecords, privateProbeRecords, opt.FirstFilePacketTimestamp)
	if err != nil {
		return nil, err
	}
	artifacts[privateNonFleetEndpointsKey] = path

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d direction.Document
	if err = json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	sqlFile, err := om.Create(flowDirectionCorrectionSQLFilename)
	if err != nil {
		return nil, err
	}
	path = sqlFile.Name()
	_, writeErr := io.WriteString(sqlFile, flowDirectionCorrectionSQLForDocument(om.NetID(), d))
	closeErr := sqlFile.Close()
	err = writeErr
	if err == nil {
		err = closeErr
	}
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
	firstPacket time.Time,
) (string, error) {
	f, err := om.Create(privateNonFleetEndpointsFilename)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", privateNonFleetEndpointsFilename, err)
	}

	path := f.Name()
	writeErr := syntrail.WritePrivateNonFleetEndpointsJSON(f, serverRecords, probeRecords, firstPacket)
	closeErr := f.Close()
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", privateNonFleetEndpointsFilename, writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", privateNonFleetEndpointsFilename, closeErr)
	}
	return path, nil
}

// directionScanOptions supplies identical qualification policy to both scans.
func directionScanOptions(fleet *syntrail.FleetSet, registry, netID string, scanOpt syntrail.ScanOptions) (syntrail.ScanOptions, error) {
	scanOpt.SyslogEligible = func(src, dst netip.Addr) bool {
		return fleet.Contains(src) && !fleet.Contains(dst) && direction.Private(dst)
	}
	scanOpt.SyslogCache = syntrail.NewSyslogCache()
	if registry != "" {
		raw, err := os.ReadFile(registry)
		if err != nil {
			return scanOpt, err
		}
		d, err := direction.Decode(raw)
		if err != nil {
			return scanOpt, err
		}
		if err = d.ValidateRegistry(d.AccountID, netID); err != nil {
			return scanOpt, err
		}
		for _, e := range d.Endpoints {
			ip, _ := netip.ParseAddr(e.IP)
			for _, b := range e.Server.Listeners {
				if b.Protocol == "udp" && b.Evidence == "syslog" {
					scanOpt.SyslogCache.Add(ip, b.Port)
				}
			}
		}
	}
	return scanOpt, nil
}
