package syntrail

import "sync"

type pollContact struct {
	client, device [4]byte
	identity       string
	clientPort     uint16
}

// PrivateUDPObservations keeps exact poll tuples for one run outside the compact
// packet records. File workers publish contacts only after a successful read.
type PrivateUDPObservations struct {
	fleet    *FleetSet
	mu       sync.Mutex
	contacts map[pollContact]struct{}
}

// NewPrivateUDPObservations enables UDP role reconciliation for the supplied fleet.
func NewPrivateUDPObservations(fleet *FleetSet) *PrivateUDPObservations {
	return &PrivateUDPObservations{fleet: fleet}
}

func (o *PrivateUDPObservations) commit(contacts map[pollContact]struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.contacts == nil {
		o.contacts = contacts
		return
	}
	for c := range contacts {
		o.contacts[c] = struct{}{}
	}
}

type returnEvidence uint8

const (
	unverifiedReturn returnEvidence = 1 << iota
	decodedResponse
	ordinaryUDP
	ignoredVPNReturn
)

func (c *Collector) observePrivateUDP(r *Record, srcPort uint16, payload []byte) {
	if c.privateUDP == nil || r.DstPort == 162 {
		return
	}
	fleet := c.privateUDP.fleet
	// Exclude fleet UDP/1194 to private client ports from daily listener
	// evidence at observation time, even when only this direction is captured.
	if srcPort == 1194 && highVPNClientPort(r.DstPort) && fleet.Contains(r.SrcAddr()) &&
		isLocalIPv4(r.DstAddr()) && !fleet.Contains(r.DstAddr()) {
		r.returnEvidence = ignoredVPNReturn
		return
	}
	if r.DstPort == 161 && fleet.Contains(r.DstAddr()) && isLocalIPv4(r.SrcAddr()) && !fleet.Contains(r.SrcAddr()) {
		if c.pollContacts == nil {
			c.pollContacts = make(map[pollContact]struct{})
		}
		c.pollContacts[pollContact{r.SrcIP, r.DstIP, r.FleetIdentity, srcPort}] = struct{}{}
		return
	}
	if srcPort != 161 || !fleet.Contains(r.SrcAddr()) || fleet.Contains(r.DstAddr()) || !isLocalIPv4(r.DstAddr()) {
		return
	}
	r.returnEvidence = unverifiedReturn
	// A poll observed in this file already establishes this reverse tuple.
	if _, ok := c.pollContacts[pollContact{r.DstIP, r.SrcIP, r.FleetIdentity, r.DstPort}]; ok {
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
func (o *PrivateUDPObservations) PrivateEndpointBehaviors(servers, inbound []Record) (listeners, targets []Record) {
	var contacts map[pollContact]struct{}
	if o != nil {
		contacts = o.contacts
	}
	for _, r := range inbound {
		if r.Protocol == ProtocolTCP || r.Protocol == 0 || (r.Protocol == ProtocolUDP && r.DstPort == 161) {
			targets = append(targets, r)
		}
	}
	listeners = servers[:0]
	for _, r := range servers {
		ev := r.returnEvidence
		if ev&decodedResponse != 0 {
			targets = append(targets, Record{SrcIP: r.DstIP, DstIP: r.SrcIP, Protocol: ProtocolUDP, DstPort: 161, FleetIdentity: r.FleetIdentity, Timestamp: r.Timestamp, MissingTime: r.MissingTime})
		}
		if ev != 0 && ev&ordinaryUDP == 0 {
			// An ignored VPN return provides no listener evidence. A mixed
			// tuple can still qualify through an unmatched UDP/161 return.
			_, matched := contacts[pollContact{r.DstIP, r.SrcIP, r.FleetIdentity, r.DstPort}]
			if ev&unverifiedReturn == 0 || matched {
				continue
			}
		}
		listeners = append(listeners, r)
	}
	clear(servers[len(listeners):])
	return listeners, targets
}
