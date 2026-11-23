package syntrail

// Each full chunk holds 640 KiB of slots on amd64. Exceptions are local to a
// chunk so their full records can be released as that chunk is decoded.
const accumulatorChunkRecords = 16 * 1024

type tcpChunk struct {
	slots      []compactTCPRecord
	exceptions []Record
}

type compactTCPRecord struct {
	fleetIdentity   string
	unixNanos       int64
	src, dst        [4]byte
	dstPort         uint16
	exception       uint16 // One-based index within this 16K chunk; zero is packed TCP.
	syslogQualified bool
	missingTime     bool
}

func packTCP(r Record) (compactTCPRecord, bool) {
	// Preserve the omitted protocol as supplied; only explicit TCP is implicit
	// in a packed slot. All captured timestamps and IPv4 values are representable.
	if r.Protocol != ProtocolTCP {
		return compactTCPRecord{}, false
	}
	return compactTCPRecord{
		fleetIdentity: r.FleetIdentity, unixNanos: r.Timestamp, src: r.SrcIP, dst: r.DstIP,
		dstPort: r.DstPort, syslogQualified: r.SyslogQualified, missingTime: r.MissingTime,
	}, true
}

func (c *tcpChunk) add(r Record) {
	slot, ok := packTCP(r)
	if !ok {
		c.exceptions = append(c.exceptions, r)
		slot.exception = uint16(len(c.exceptions))
	}
	c.slots = append(c.slots, slot)
}

func (c tcpChunk) unpackInto(dst []Record) int {
	for i, slot := range c.slots {
		if slot.exception != 0 {
			dst[i] = c.exceptions[slot.exception-1]
			continue
		}
		dst[i] = Record{
			FleetIdentity: slot.fleetIdentity, SrcIP: slot.src, DstIP: slot.dst,
			DstPort: slot.dstPort, Protocol: ProtocolTCP, Timestamp: slot.unixNanos, MissingTime: slot.missingTime,
			SyslogQualified: slot.syslogQualified,
		}
	}
	return len(c.slots)
}
