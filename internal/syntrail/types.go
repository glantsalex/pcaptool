package syntrail

import (
	"net/netip"
	"time"
)

// Protocol identifies the transport protocol observed for a trail record.
type Protocol string

const (
	// ProtocolTCP identifies TCP traffic.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP identifies UDP traffic.
	ProtocolUDP Protocol = "udp"
)

// Record represents observed TCP SYN attempt evidence or inferred UDP edge
// evidence from captured traffic.
type Record struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	DstPort   uint16
	Protocol  Protocol
	Timestamp time.Time
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
