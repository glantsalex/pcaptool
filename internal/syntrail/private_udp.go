package syntrail

import "net/netip"

// pollPorts is shared by records aggregated under one manager/device key.
type pollPorts struct{ ports map[uint16]struct{} }

func (p *pollPorts) contains(port uint16) bool {
	if p == nil {
		return false
	}
	_, ok := p.ports[port]
	return ok
}

type returnEvidence uint8

const (
	unverifiedReturn returnEvidence = 1 << iota
	decodedResponse
	ordinaryUDP
)

func (c *Collector) observePrivateUDP(r *Record, srcPort uint16, payload []byte) {
	fleet := c.privateUDPFleet
	if fleet == nil || r.DstPort == 162 || (r.DstPort != 161 && srcPort != 161) {
		return
	}
	if r.DstPort == 161 && fleet.Contains(r.DstIP) && !fleet.Contains(r.SrcIP) {
		key := observedRecordKey{fleetIdentity: r.FleetIdentity, srcIP: r.SrcIP, dstIP: r.DstIP, dstPort: 161, protocol: ProtocolUDP}
		ports := c.udpRecords[key].pollPorts
		if ports == nil {
			ports = &pollPorts{ports: make(map[uint16]struct{})}
		}
		ports.ports[srcPort] = struct{}{}
		r.pollPorts = ports
		return
	}
	if srcPort != 161 || !fleet.Contains(r.SrcIP) || fleet.Contains(r.DstIP) || !isLocalIPv4(r.DstIP) {
		return
	}
	r.returnEvidence = unverifiedReturn
	// A poll observed in this file already establishes this reverse tuple.
	key := observedRecordKey{fleetIdentity: r.FleetIdentity, srcIP: r.DstIP, dstIP: r.SrcIP, dstPort: 161, protocol: ProtocolUDP}
	if c.udpRecords[key].pollPorts.contains(r.DstPort) {
		return
	}
	if isSNMPResponse(payload) {
		r.returnEvidence = decodedResponse
	}
}

// PrivateEndpointBehaviors selects daily targets and removes reply-only
// listeners. servers is an owned slice. inbound is borrowed. Reconciliation
// runs after the file workers merge, independent of packet processing order.
func PrivateEndpointBehaviors(servers, inbound []Record) (listeners, targets []Record) {
	type peer struct {
		manager, device netip.Addr
		identity        string
	}
	polls := make(map[peer]*pollPorts)
	for _, r := range inbound {
		if r.Protocol == ProtocolTCP || r.Protocol == "" || (r.Protocol == ProtocolUDP && r.DstPort == 161) {
			targets = append(targets, r)
		}
		if r.pollPorts != nil {
			polls[peer{r.SrcIP, r.DstIP, r.FleetIdentity}] = r.pollPorts
		}
	}
	listeners = servers[:0]
	for _, r := range servers {
		ev := r.returnEvidence
		if ev&decodedResponse != 0 {
			targets = append(targets, Record{SrcIP: r.DstIP, DstIP: r.SrcIP, Protocol: ProtocolUDP, DstPort: 161, FleetIdentity: r.FleetIdentity, Timestamp: r.Timestamp})
		}
		if ev != 0 && ev&ordinaryUDP == 0 {
			if ev&unverifiedReturn == 0 {
				continue
			}
			if polls[peer{r.DstIP, r.SrcIP, r.FleetIdentity}].contains(r.DstPort) {
				continue
			}
		}
		listeners = append(listeners, r)
	}
	clear(servers[len(listeners):])
	return listeners, targets
}
