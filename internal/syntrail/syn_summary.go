package syntrail

// SYNSummaryPolicy selects evidence needed by the non-debug fleet artifacts.
// Workers and the coordinator share the immutable policy, each with its own set.
type SYNSummaryPolicy struct {
	Fleet             FleetSet
	CountIMSI         bool
	FTPControlPorts   map[uint16]struct{}
	FTPPassiveMinPort uint16
}

type synSummaryKey struct {
	identity          string
	endpoint, fleetIP [4]byte
	port              uint16
	probe             bool
}

type synSummary struct {
	policy *SYNSummaryPolicy
	seen   map[synSummaryKey]struct{}
}

// keep admits one real representative for each contribution to the summary
// writers. Neither capture time, source port nor TCP sequence affects them.
func (s *synSummary) keep(r Record) bool {
	p := s.policy
	bucket, ok := Classify(r, p.Fleet)
	if !ok || bucket == BucketFleetToFleet {
		return false
	}
	k := synSummaryKey{port: r.DstPort}
	if bucket == BucketPrivateNonFleetToFleet {
		k.endpoint, k.fleetIP, k.probe = r.SrcIP, r.DstIP, true
	} else {
		k.endpoint, k.fleetIP = r.DstIP, r.SrcIP
	}

	countDevice := k.probe || isLocalIPv4(r.DstAddr())
	if countDevice && p.CountIMSI {
		k.identity = r.FleetIdentity
	}
	// FTP suppression consults the original source/destination pair, even
	// when the control channel first appears in a later capture.
	_, control := p.FTPControlPorts[r.DstPort]
	needPair := !k.probe && (control || r.DstPort >= p.FTPPassiveMinPort)
	if !needPair && (!countDevice || k.identity != "") {
		k.fleetIP = [4]byte{}
	}
	if _, exists := s.seen[k]; exists {
		return false
	}
	if s.seen == nil {
		s.seen = make(map[synSummaryKey]struct{})
	}
	s.seen[k] = struct{}{}
	return true
}
