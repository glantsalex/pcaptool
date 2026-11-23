package syntrail

import (
	"fmt"
	"math"
	"net/netip"
	"time"
)

// Protocol identifies the captured transport protocol by its IP protocol number.
// Zero preserves an omitted protocol; existing output normalization treats it as TCP.
type Protocol uint8

const (
	// ProtocolTCP identifies TCP traffic.
	ProtocolTCP Protocol = 6
	// ProtocolUDP identifies UDP traffic.
	ProtocolUDP Protocol = 17
)

// String returns the transport name used by trail and summary outputs.
func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return ""
	}
}

// Record is a captured IPv4 TCP SYN attempt or inferred UDP edge. Its 48-byte
// layout on amd64 keeps the temporary SYN header until the coordinator consumes it.
// IP bytes are in network order. Timestamp is exact signed Unix nanoseconds;
// zero is the epoch, while MissingTime denotes a missing capture timestamp, even when packet metadata exists.
type Record struct {
	FleetIdentity   string // Resolved at packet time, before UDP aggregation.
	Timestamp       int64
	SrcIP           [4]byte
	DstIP           [4]byte
	synSeq          uint32
	DstPort         uint16
	synSrcPort      uint16
	Protocol        Protocol
	SyslogQualified bool
	MissingTime     bool
	hasSYNHeader    bool
}

// SrcAddr returns the source IPv4 address.
func (r Record) SrcAddr() netip.Addr { return netip.AddrFrom4(r.SrcIP) }

// DstAddr returns the destination IPv4 address.
func (r Record) DstAddr() netip.Addr { return netip.AddrFrom4(r.DstIP) }

var (
	minRecordTime = time.Unix(0, math.MinInt64).UTC()
	maxRecordTime = time.Unix(0, math.MaxInt64).UTC()
)

// SetTimestamp stores a capture timestamp without losing sub-millisecond precision.
// Readers use time.Time{} for missing time. A supplied time outside the signed
// nanosecond range is rejected before UnixNano, whose result would be undefined.
func (r *Record) SetTimestamp(ts time.Time) error {
	if ts.IsZero() {
		r.Timestamp, r.MissingTime = 0, true
		return nil
	}
	if ts.Before(minRecordTime) || ts.After(maxRecordTime) {
		return fmt.Errorf("capture timestamp %s is outside signed Unix nanosecond range", ts.Format(time.RFC3339Nano))
	}
	r.Timestamp, r.MissingTime = ts.UnixNano(), false
	return nil
}

// CaptureTime reconstructs UTC time, including the historical missing-time value.
func (r Record) CaptureTime() time.Time {
	if r.MissingTime {
		return time.Time{}
	}
	return time.Unix(0, r.Timestamp).UTC()
}

// TimeBefore compares capture instants, with absent timestamps before dated ones.
func (r Record) TimeBefore(other Record) bool {
	if r.MissingTime != other.MissingTime {
		return r.MissingTime
	}
	return !r.MissingTime && r.Timestamp < other.Timestamp
}

// TimeEqual reports equal capture instants or two absent timestamps.
func (r Record) TimeEqual(other Record) bool {
	return r.MissingTime == other.MissingTime && (r.MissingTime || r.Timestamp == other.Timestamp)
}

// Bucket identifies a SYN trail classification bucket.
type Bucket string

const (
	// BucketFleetToNonFleet contains records from fleet hosts to non-fleet destinations.
	BucketFleetToNonFleet Bucket = "fleet_to_non_fleet"
	// BucketFleetToFleet contains records from fleet hosts to fleet destinations.
	BucketFleetToFleet Bucket = "fleet_to_fleet"
	// BucketPrivateNonFleetToFleet contains records from private non-fleet hosts to fleet destinations.
	BucketPrivateNonFleetToFleet Bucket = "private_non_fleet_to_fleet"
)

// BucketedRecords groups records by their classification bucket.
type BucketedRecords map[Bucket][]Record
