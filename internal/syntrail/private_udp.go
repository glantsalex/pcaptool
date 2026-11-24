package syntrail

import "net/netip"

// clientPorts is shared by records aggregated under one private client/fleet service key.
type clientPorts struct{ ports map[uint16]struct{} }

func (p *clientPorts) contains(port uint16) bool {
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
	ignoredVPNReturn
)

func (c *Collector) observePrivateUDP(r *Record, srcPort uint16, payload []byte) {
	fleet := c.privateUDPFleet
	if fleet == nil || r.DstPort == 162 {
		return
	}
	// Exclude fleet UDP/1194 to private client ports from daily listener
	// evidence at observation time, even when only this direction is captured.
	if srcPort == 1194 && highVPNClientPort(r.DstPort) && fleet.Contains(r.SrcIP) &&
		isLocalIPv4(r.DstIP) && !fleet.Contains(r.DstIP) {
		r.returnEvidence = ignoredVPNReturn
		return
	}
	if r.DstPort == 161 && fleet.Contains(r.DstIP) && !fleet.Contains(r.SrcIP) {
		key := observedRecordKey{fleetIdentity: r.FleetIdentity, srcIP: r.SrcIP, dstIP: r.DstIP, dstPort: r.DstPort, protocol: ProtocolUDP}
		ports := c.udpRecords[key].clientPorts
		if ports == nil {
			ports = &clientPorts{ports: make(map[uint16]struct{})}
		}
		ports.ports[srcPort] = struct{}{}
		r.clientPorts = ports
		return
	}
	if srcPort != 161 || !fleet.Contains(r.SrcIP) || fleet.Contains(r.DstIP) || !isLocalIPv4(r.DstIP) {
		return
	}
	r.returnEvidence = unverifiedReturn
	// A poll observed in this file already establishes this reverse tuple.
	key := observedRecordKey{fleetIdentity: r.FleetIdentity, srcIP: r.DstIP, dstIP: r.SrcIP, dstPort: 161, protocol: ProtocolUDP}
	if c.udpRecords[key].clientPorts.contains(r.DstPort) {
		return
	}
	if isSNMPResponse(payload) {
		r.returnEvidence = decodedResponse
	}
}

func highVPNClientPort(port uint16) bool {
	return port >= 1024 && port != 1194
}

// PrivateEndpointBehaviors selects daily targets and removes reply-only
// listeners. servers is an owned slice. inbound is borrowed. Reconciliation
// runs after the file workers merge, independent of packet processing order.
func PrivateEndpointBehaviors(servers, inbound []Record) (listeners, targets []Record) {
	type peer struct {
		client, device netip.Addr
		identity       string
	}
	contacts := make(map[peer]*clientPorts)
	for _, r := range inbound {
		if r.Protocol == ProtocolTCP || r.Protocol == "" || (r.Protocol == ProtocolUDP && r.DstPort == 161) {
			targets = append(targets, r)
		}
		if r.clientPorts != nil {
			contacts[peer{r.SrcIP, r.DstIP, r.FleetIdentity}] = r.clientPorts
		}
	}
	listeners = servers[:0]
	for _, r := range servers {
		ev := r.returnEvidence
		if ev&decodedResponse != 0 {
			targets = append(targets, Record{SrcIP: r.DstIP, DstIP: r.SrcIP, Protocol: ProtocolUDP, DstPort: 161, FleetIdentity: r.FleetIdentity, Timestamp: r.Timestamp})
		}
		if ev != 0 && ev&ordinaryUDP == 0 {
			// An ignored VPN return provides no listener evidence. A mixed
			// tuple can still qualify through an unmatched UDP/161 return.
			if ev&unverifiedReturn == 0 || contacts[peer{r.DstIP, r.SrcIP, r.FleetIdentity}].contains(r.DstPort) {
				continue
			}
		}
		listeners = append(listeners, r)
	}
	clear(servers[len(listeners):])
	return listeners, targets
}
