package lsm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/logicalservice"
)

// Stats reports observation counts, not inferred connection or device health.
type Stats struct {
	Input        int `json:"source_observations"`
	Public       int `json:"public_observations"`
	Excluded     int `json:"excluded_non_public_observations"`
	Classified   int `json:"classified_observations"`
	Unclassified int `json:"unclassified_observations"`
	Issuers      int `json:"issuers"`
	Services     int `json:"services"`
	Edges        int `json:"device_service_edges"`
}

// Map is the canonical full LSM; all other representations derive from it.
type Map struct {
	ArtifactType string   `json:"artifact_type"`
	Schema       int      `json:"map_schema_revision"`
	StreamID     string   `json:"stream_id"`
	CaptureDate  string   `json:"capture_date"`
	Encoding     string   `json:"encoding"`
	Devices      []Device `json:"devices"`
}

// Device groups eligible observations by their capture issuer address.
type Device struct {
	Issuer       string        `json:"issuer"`
	Services     []Edge        `json:"services"`
	Unclassified []Observation `json:"unclassified_endpoints"`
}

// Edge preserves the observed members of one device-to-service relationship.
type Edge struct {
	ServiceID   string        `json:"svc_id"`
	ServiceName string        `json:"svc_name"`
	Endpoints   []Observation `json:"endpoints"`
}

// Observation preserves each eligible NTM row, including duplicate rows.
// Provenance source/index are deliberately excluded from delivery maps.
type Observation struct {
	IP                string `json:"dst_ip"`
	DNS               string `json:"dns_name"`
	Protocol          string `json:"proto"`
	Port              uint16 `json:"port"`
	SeenAt            string `json:"seen_at"`
	RuleID            string `json:"rule_id,omitempty"`
	Reason            string `json:"reason,omitempty"`
	ObservedDNS       string `json:"observed_dns_name,omitempty"`
	NormalizedDNS     string `json:"normalized_dns_name,omitempty"`
	NormalizationRule string `json:"normalization_rule_id,omitempty"`
	CNAMEChain        string `json:"cname_chain,omitempty"`
}

// Build consumes finalized NTM without modifying it. Invalid destination IPs,
// classifier conflicts and cancellation fail the whole LSM, never silently
// produce partial classifications. Non-public rows are excluded before classification.
func Build(ctx context.Context, rows []dns.TopologyEntry, definitions *logicalservice.Definitions, stream, date string) (Map, Stats, error) {
	model := Map{ArtifactType: "device_coarse_services_map", Schema: 3, StreamID: stream,
		CaptureDate: date, Encoding: "full", Devices: []Device{}}
	stats := Stats{Input: len(rows)}
	classifier, err := definitions.Classifier()
	if err != nil {
		return Map{}, Stats{}, err
	}
	names := make(map[string]string, len(definitions.Services))
	for _, s := range definitions.Services {
		names[s.ID] = s.Name
	}
	indices := make([]int, 0, len(rows))
	endpoints := make([]logicalservice.Endpoint, 0, len(rows))
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return Map{}, Stats{}, err
		}
		a, err := netip.ParseAddr(row.DestinationIP)
		if err != nil {
			return Map{}, Stats{}, fmt.Errorf("LSM NTM row %d destination: %w", i, err)
		}
		if !PublicDestination(a) {
			stats.Excluded++
			continue
		}
		if _, err := netip.ParseAddr(row.IssuerIP); err != nil {
			return Map{}, Stats{}, fmt.Errorf("LSM NTM row %d issuer: %w", i, err)
		}
		indices = append(indices, i)
		endpoints = append(endpoints, logicalservice.Endpoint{SubjectID: row.IssuerIP, DNS: row.DNSName,
			DstIP: row.DestinationIP, Protocol: row.Protocol, DstPort: row.Port})
	}
	result, err := classifier.Classify(ctx, endpoints)
	if err != nil {
		return Map{}, Stats{}, err
	}
	stats.Public = len(indices)
	type deviceBuilder struct {
		edges        map[string]*Edge
		unclassified []Observation
	}
	devices := map[string]*deviceBuilder{}
	usedServices := map[string]bool{}
	for i, index := range indices {
		if err := ctx.Err(); err != nil {
			return Map{}, Stats{}, err
		}
		row := rows[index]
		dev := devices[row.IssuerIP]
		if dev == nil {
			dev = &deviceBuilder{edges: map[string]*Edge{}, unclassified: []Observation{}}
			devices[row.IssuerIP] = dev
		}
		observation := Observation{IP: row.DestinationIP, DNS: row.DNSName, Protocol: row.Protocol,
			Port: row.Port, SeenAt: row.ObservedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			ObservedDNS: row.ObservedDNSName, NormalizedDNS: row.NormalizedDNSName,
			NormalizationRule: row.NormalizationRuleID, CNAMEChain: row.CNAMEChain}
		entry := result.Entries[i]
		if !entry.Matched {
			stats.Unclassified++
			observation.Reason = "no_matching_rule"
			if strings.TrimSpace(row.DNSName) == "" {
				observation.Reason = "no_dns_attribution"
			}
			dev.unclassified = append(dev.unclassified, observation)
			continue
		}
		stats.Classified++
		sid := entry.Decision.LogicalServiceID
		usedServices[sid] = true
		observation.RuleID = entry.Decision.MatchedRuleID
		edge := dev.edges[sid]
		if edge == nil {
			edge = &Edge{ServiceID: sid, ServiceName: names[sid], Endpoints: []Observation{}}
			dev.edges[sid] = edge
		}
		edge.Endpoints = append(edge.Endpoints, observation)
	}
	for _, issuer := range sortedKeys(devices) {
		dev := devices[issuer]
		out := Device{Issuer: issuer, Services: []Edge{}, Unclassified: dev.unclassified}
		for _, sid := range sortedKeys(dev.edges) {
			edge := dev.edges[sid]
			sortObservations(edge.Endpoints)
			out.Services = append(out.Services, *edge)
			stats.Edges++
		}
		sortObservations(out.Unclassified)
		model.Devices = append(model.Devices, out)
	}
	stats.Issuers, stats.Services = len(model.Devices), len(usedServices)
	return model, stats, ctx.Err()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortObservations(rows []Observation) {
	// Precompute tie-break keys once rather than marshal inside O(n log n) comparisons.
	type keyed struct {
		row Observation
		key string
	}
	keys := make([]keyed, len(rows))
	for i, row := range rows {
		b, _ := json.Marshal(row)
		keys[i] = keyed{row, string(b)}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].key < keys[j].key })
	for i := range keys {
		rows[i] = keys[i].row
	}
}

// ShortService is one observed service/protocol/port combination.
type ShortService struct {
	ServiceID   string `json:"svc_id"`
	ServiceName string `json:"svc_name"`
	Protocol    string `json:"proto"`
	Port        uint16 `json:"port"`
}

// ShortDevice is the minimal topology view for an eligible issuer.
type ShortDevice struct {
	Issuer   string         `json:"issuer_id"`
	Services []ShortService `json:"services"`
}

// Short derives unique service/transport tuples exclusively from observations.
func (m Map) Short() []ShortDevice {
	out := make([]ShortDevice, 0, len(m.Devices))
	for _, d := range m.Devices {
		device := ShortDevice{Issuer: d.Issuer, Services: []ShortService{}}
		for _, e := range d.Services {
			seen := map[ShortService]bool{}
			for _, o := range e.Endpoints {
				seen[ShortService{e.ServiceID, e.ServiceName, o.Protocol, o.Port}] = true
			}
			for s := range seen {
				device.Services = append(device.Services, s)
			}
		}
		sort.Slice(device.Services, func(i, j int) bool {
			a, b := device.Services[i], device.Services[j]
			if a.ServiceID != b.ServiceID {
				return a.ServiceID < b.ServiceID
			}
			if a.Protocol != b.Protocol {
				return a.Protocol < b.Protocol
			}
			return a.Port < b.Port
		})
		out = append(out, device)
	}
	return out
}
