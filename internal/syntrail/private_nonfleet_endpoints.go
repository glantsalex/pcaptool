package syntrail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const privateNonFleetEndpointsSchemaVersion = 1

// PrivateNonFleetEndpointsDocument is the versioned private non-fleet endpoint artifact.
type PrivateNonFleetEndpointsDocument struct {
	SchemaVersion int `json:"schema_version"`
	// SnapshotTime is midnight UTC in Unix milliseconds, or 0 if unknown.
	SnapshotTime int64                     `json:"snapshot_time"`
	Endpoints    []PrivateNonFleetEndpoint `json:"endpoints"`
}

// PrivateNonFleetEndpoint describes all observed server and probe behaviors for one IPv4 endpoint.
type PrivateNonFleetEndpoint struct {
	IP     string         `json:"ip"`
	Server ServerBehavior `json:"server"`
	Probe  ProbeBehavior  `json:"probe"`
}

// ServerBehavior contains transport listeners serving fleet devices.
type ServerBehavior struct {
	Listeners []TransportBehavior `json:"listeners"`
}

// ProbeBehavior contains destination transports targeted on fleet devices.
type ProbeBehavior struct {
	Targets []TransportBehavior `json:"targets"`
}

// TransportBehavior describes one protocol/port behavior and its distinct fleet IPv4 cardinality.
type TransportBehavior struct {
	Protocol          string `json:"protocol"`
	Port              uint16 `json:"port"`
	FleetDevicesCount int    `json:"fleet_devices_count"`
}

type transportPortKey struct {
	protocol string
	port     uint16
}

type endpointAccumulator struct {
	listeners map[transportPortKey]map[netip.Addr]struct{}
	targets   map[transportPortKey]map[netip.Addr]struct{}
}

// WritePrivateNonFleetEndpointsJSON writes schema v1 endpoint behavior JSON.
// Server records must already have the existing server-summary filters applied;
// probe records must already be restricted to the existing TCP qualification path.
// firstPacket is the first packet timestamp in the first discovered capture,
// before admission filtering. Its UTC calendar day is encoded as Unix milliseconds;
// a zero timestamp produces snapshot_time 0 (unknown).
func WritePrivateNonFleetEndpointsJSON(w io.Writer, serverRecords, probeRecords []Record, firstPacket time.Time) error {
	document := buildPrivateNonFleetEndpointsDocument(serverRecords, probeRecords)
	if !firstPacket.IsZero() {
		utc := firstPacket.UTC()
		document.SnapshotTime = time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC).UnixMilli()
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode private non-fleet endpoints JSON: %w", err)
	}
	return nil
}

func buildPrivateNonFleetEndpointsDocument(serverRecords, probeRecords []Record) PrivateNonFleetEndpointsDocument {
	byIP := make(map[netip.Addr]*endpointAccumulator)
	for _, record := range serverRecords {
		addEndpointEvidence(byIP, record.DstIP, record.SrcIP, record.Protocol, record.DstPort, true)
	}
	for _, record := range probeRecords {
		addEndpointEvidence(byIP, record.SrcIP, record.DstIP, record.Protocol, record.DstPort, false)
	}

	addresses := make([]netip.Addr, 0, len(byIP))
	for addr := range byIP {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return compareAddr(addresses[i], addresses[j]) < 0
	})

	document := PrivateNonFleetEndpointsDocument{
		SchemaVersion: privateNonFleetEndpointsSchemaVersion,
		Endpoints:     make([]PrivateNonFleetEndpoint, 0, len(addresses)),
	}
	for _, addr := range addresses {
		accumulator := byIP[addr]
		document.Endpoints = append(document.Endpoints, PrivateNonFleetEndpoint{
			IP: addr.String(),
			Server: ServerBehavior{
				Listeners: transportBehaviors(accumulator.listeners),
			},
			Probe: ProbeBehavior{
				Targets: transportBehaviors(accumulator.targets),
			},
		})
	}
	return document
}

func addEndpointEvidence(
	byIP map[netip.Addr]*endpointAccumulator,
	endpointIP netip.Addr,
	fleetIP netip.Addr,
	protocol Protocol,
	port uint16,
	server bool,
) {
	if !endpointIP.Is4() || !fleetIP.Is4() {
		return
	}
	endpointIP = endpointIP.Unmap()
	fleetIP = fleetIP.Unmap()
	accumulator := byIP[endpointIP]
	if accumulator == nil {
		accumulator = &endpointAccumulator{
			listeners: make(map[transportPortKey]map[netip.Addr]struct{}),
			targets:   make(map[transportPortKey]map[netip.Addr]struct{}),
		}
		byIP[endpointIP] = accumulator
	}

	key := transportPortKey{
		protocol: normalizedProtocolName(protocol),
		port:     port,
	}
	behaviors := accumulator.targets
	if server {
		behaviors = accumulator.listeners
	}
	fleetDevices := behaviors[key]
	if fleetDevices == nil {
		fleetDevices = make(map[netip.Addr]struct{})
		behaviors[key] = fleetDevices
	}
	fleetDevices[fleetIP] = struct{}{}
}

func transportBehaviors(sets map[transportPortKey]map[netip.Addr]struct{}) []TransportBehavior {
	behaviors := make([]TransportBehavior, 0, len(sets))
	for key, fleetDevices := range sets {
		if len(fleetDevices) == 0 {
			continue
		}
		behaviors = append(behaviors, TransportBehavior{
			Protocol:          key.protocol,
			Port:              key.port,
			FleetDevicesCount: len(fleetDevices),
		})
	}
	sort.Slice(behaviors, func(i, j int) bool {
		if behaviors[i].Port != behaviors[j].Port {
			return behaviors[i].Port < behaviors[j].Port
		}
		return behaviors[i].Protocol < behaviors[j].Protocol
	})
	return behaviors
}

func normalizedProtocolName(protocol Protocol) string {
	if protocol == "" {
		return string(ProtocolTCP)
	}
	return strings.ToLower(string(protocol))
}
