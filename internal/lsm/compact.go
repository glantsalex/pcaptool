package lsm

import "fmt"

// ServiceIdentity binds a stable service ID to its display name.
type ServiceIdentity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Dictionaries contains the zero-based string tables local to one compact map.
type Dictionaries struct {
	IPs      []string          `json:"ips"`
	DNS      []string          `json:"dns_names"`
	Rules    []string          `json:"rules"`
	Services []ServiceIdentity `json:"services"`
}

// CompactMap replaces repeated identity strings with dictionary references.
type CompactMap struct {
	ArtifactType string          `json:"artifact_type"`
	Schema       int             `json:"map_schema_revision"`
	StreamID     string          `json:"stream_id"`
	CaptureDate  string          `json:"capture_date"`
	Encoding     string          `json:"encoding"`
	Dictionaries Dictionaries    `json:"dictionaries"`
	Devices      []CompactDevice `json:"devices"`
}

// CompactDevice references an issuer in the IP dictionary.
type CompactDevice struct {
	Issuer       *int                 `json:"issuer_ref"`
	Services     []CompactEdge        `json:"services"`
	Unclassified []CompactObservation `json:"unclassified_endpoints"`
}

// CompactEdge references a service in the paired service dictionary.
type CompactEdge struct {
	Service   *int                 `json:"svc_ref"`
	Endpoints []CompactObservation `json:"endpoints"`
}

// CompactObservation retains transport and evidence with indexed identities.
type CompactObservation struct {
	IP                *int   `json:"dst_ip_ref"`
	DNS               *int   `json:"dns_ref"`
	Rule              *int   `json:"rule_ref,omitempty"`
	Protocol          string `json:"proto"`
	Port              uint16 `json:"port"`
	SeenAt            string `json:"seen_at"`
	Reason            string `json:"reason,omitempty"`
	ObservedDNS       *int   `json:"observed_dns_ref,omitempty"`
	NormalizedDNS     *int   `json:"normalized_dns_ref,omitempty"`
	NormalizationRule *int   `json:"normalization_rule_ref,omitempty"`
	CNAMEChain        string `json:"cname_chain,omitempty"`
}

// Compact uses sorted, zero-based, file-local dictionaries. Missing DNS is null,
// not index zero. Observation ordering and multiplicity are preserved.
func (m Map) Compact() (CompactMap, error) {
	ips, dnsNames, rules := map[string]bool{}, map[string]bool{}, map[string]bool{}
	services := map[string]string{}
	add := func(o Observation) {
		ips[o.IP] = true
		for _, v := range []string{o.DNS, o.ObservedDNS, o.NormalizedDNS} {
			if v != "" {
				dnsNames[v] = true
			}
		}
		for _, v := range []string{o.RuleID, o.NormalizationRule} {
			if v != "" {
				rules[v] = true
			}
		}
	}
	for _, d := range m.Devices {
		ips[d.Issuer] = true
		for _, e := range d.Services {
			if name, ok := services[e.ServiceID]; ok && name != e.ServiceName {
				return CompactMap{}, fmt.Errorf("inconsistent service name for %q", e.ServiceID)
			}
			services[e.ServiceID] = e.ServiceName
			for _, o := range e.Endpoints {
				add(o)
			}
		}
		for _, o := range d.Unclassified {
			add(o)
		}
	}
	out := CompactMap{ArtifactType: m.ArtifactType, Schema: m.Schema, StreamID: m.StreamID, CaptureDate: m.CaptureDate,
		Encoding: "dictionary", Devices: []CompactDevice{},
		Dictionaries: Dictionaries{IPs: sortedKeys(ips), DNS: sortedKeys(dnsNames), Rules: sortedKeys(rules), Services: []ServiceIdentity{}}}
	index := func(values []string) map[string]int {
		out := map[string]int{}
		for i, v := range values {
			out[v] = i
		}
		return out
	}
	ipIndex, dnsIndex, ruleIndex := index(out.Dictionaries.IPs), index(out.Dictionaries.DNS), index(out.Dictionaries.Rules)
	svcIndex := map[string]int{}
	for _, sid := range sortedKeys(services) {
		svcIndex[sid] = len(out.Dictionaries.Services)
		out.Dictionaries.Services = append(out.Dictionaries.Services, ServiceIdentity{sid, services[sid]})
	}
	ref := func(value string, indices map[string]int) *int {
		if value == "" {
			return nil
		}
		i := indices[value]
		return &i
	}
	encode := func(obs []Observation) []CompactObservation {
		result := make([]CompactObservation, 0, len(obs))
		for _, o := range obs {
			result = append(result, CompactObservation{IP: ref(o.IP, ipIndex), DNS: ref(o.DNS, dnsIndex), Rule: ref(o.RuleID, ruleIndex),
				Protocol: o.Protocol, Port: o.Port, SeenAt: o.SeenAt, Reason: o.Reason,
				ObservedDNS: ref(o.ObservedDNS, dnsIndex), NormalizedDNS: ref(o.NormalizedDNS, dnsIndex),
				NormalizationRule: ref(o.NormalizationRule, ruleIndex), CNAMEChain: o.CNAMEChain})
		}
		return result
	}
	for _, d := range m.Devices {
		dev := CompactDevice{Issuer: ref(d.Issuer, ipIndex), Services: []CompactEdge{}, Unclassified: encode(d.Unclassified)}
		for _, e := range d.Services {
			dev.Services = append(dev.Services, CompactEdge{Service: ref(e.ServiceID, svcIndex), Endpoints: encode(e.Endpoints)})
		}
		out.Devices = append(out.Devices, dev)
	}
	return out, nil
}

// Expand validates dictionary references and restores the canonical full model.
func (m CompactMap) Expand() (Map, error) {
	fail := func(err error) (Map, error) { return Map{}, err }
	if m.Schema != 3 || m.Encoding != "dictionary" {
		return fail(fmt.Errorf("unsupported LSM encoding/schema"))
	}
	for _, values := range [][]string{m.Dictionaries.IPs, m.Dictionaries.DNS, m.Dictionaries.Rules} {
		seen := map[string]bool{}
		for _, v := range values {
			if v == "" || seen[v] {
				return fail(fmt.Errorf("empty or duplicate dictionary value"))
			}
			seen[v] = true
		}
	}
	seen := map[string]bool{}
	for _, s := range m.Dictionaries.Services {
		if s.ID == "" || s.Name == "" || seen[s.ID] {
			return fail(fmt.Errorf("invalid service dictionary"))
		}
		seen[s.ID] = true
	}
	resolve := func(values []string, i int) (string, error) {
		if i < 0 || i >= len(values) {
			return "", fmt.Errorf("dictionary index %d out of range", i)
		}
		return values[i], nil
	}
	optional := func(values []string, i *int) (string, error) {
		if i == nil {
			return "", nil
		}
		return resolve(values, *i)
	}
	decode := func(obs []CompactObservation) ([]Observation, error) {
		out := make([]Observation, 0, len(obs))
		for _, o := range obs {
			if o.IP == nil {
				return nil, fmt.Errorf("missing destination reference")
			}
			ip, err := resolve(m.Dictionaries.IPs, *o.IP)
			if err != nil {
				return nil, err
			}
			dns, err := optional(m.Dictionaries.DNS, o.DNS)
			if err != nil {
				return nil, err
			}
			rule, err := optional(m.Dictionaries.Rules, o.Rule)
			if err != nil {
				return nil, err
			}
			observed, err := optional(m.Dictionaries.DNS, o.ObservedDNS)
			if err != nil {
				return nil, err
			}
			normalized, err := optional(m.Dictionaries.DNS, o.NormalizedDNS)
			if err != nil {
				return nil, err
			}
			normRule, err := optional(m.Dictionaries.Rules, o.NormalizationRule)
			if err != nil {
				return nil, err
			}
			out = append(out, Observation{IP: ip, DNS: dns, RuleID: rule, Protocol: o.Protocol, Port: o.Port, SeenAt: o.SeenAt,
				Reason: o.Reason, ObservedDNS: observed, NormalizedDNS: normalized, NormalizationRule: normRule, CNAMEChain: o.CNAMEChain})
		}
		return out, nil
	}
	out := Map{ArtifactType: m.ArtifactType, Schema: m.Schema, StreamID: m.StreamID, CaptureDate: m.CaptureDate, Encoding: "full", Devices: []Device{}}
	for _, d := range m.Devices {
		if d.Issuer == nil {
			return fail(fmt.Errorf("missing issuer reference"))
		}
		issuer, err := resolve(m.Dictionaries.IPs, *d.Issuer)
		if err != nil {
			return fail(err)
		}
		unclassified, err := decode(d.Unclassified)
		if err != nil {
			return fail(err)
		}
		dev := Device{Issuer: issuer, Services: []Edge{}, Unclassified: unclassified}
		for _, e := range d.Services {
			if e.Service == nil || *e.Service < 0 || *e.Service >= len(m.Dictionaries.Services) {
				return fail(fmt.Errorf("service reference out of range"))
			}
			s := m.Dictionaries.Services[*e.Service]
			obs, err := decode(e.Endpoints)
			if err != nil {
				return fail(err)
			}
			dev.Services = append(dev.Services, Edge{ServiceID: s.ID, ServiceName: s.Name, Endpoints: obs})
		}
		out.Devices = append(out.Devices, dev)
	}
	return out, nil
}
