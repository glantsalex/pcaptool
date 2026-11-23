package syntrail

// All keys come from decoded IPv4 SYNs. Grouping by the packet-time IMSI
// stores the identity once per subscriber. The empty identity is its own group.
type synAttemptKey struct {
	src, dst         [4]byte
	srcPort, dstPort uint16
	seq              uint32
}

type synAttempts map[string]map[synAttemptKey]struct{}

// keep consumes the temporary wire header on the first SYN for this key.
// A caller-supplied Record without a header cannot establish a retransmission.
func (seen *synAttempts) keep(r *Record) bool {
	if !r.hasSYNHeader {
		return true
	}
	if *seen == nil {
		*seen = make(synAttempts)
	}
	keys := (*seen)[r.FleetIdentity]
	if keys == nil {
		keys = make(map[synAttemptKey]struct{})
		(*seen)[r.FleetIdentity] = keys
	}
	key := synAttemptKey{
		src: r.SrcIP, dst: r.DstIP,
		srcPort: r.synSrcPort, dstPort: r.DstPort, seq: r.synSeq,
	}
	if _, exists := keys[key]; exists {
		return false
	}
	keys[key] = struct{}{}
	r.hasSYNHeader, r.synSrcPort, r.synSeq = false, 0, 0
	return true
}

// Single-file callers own the batch. Compact it in place without constructing
// the global storage used by multi-file scans.
func singleFileRecords(batch []Record) []Record {
	var seen synAttempts
	out := batch[:0]
	for _, r := range batch {
		if seen.keep(&r) {
			out = append(out, r)
		}
	}
	clear(batch[len(out):])
	return out
}
