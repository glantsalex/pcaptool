package syntrail

// SYNSummaryCount reports retained TCP summary keys to the owning coordinator.
func (a *Accumulator) SYNSummaryCount() int { return len(a.summary.seen) }

// RecordCount reports the retained record count without materializing it.
// Like Add and consuming methods, it requires exclusive accumulator ownership.
func (a *Accumulator) RecordCount() int {
	return len(a.tcpChunks)*accumulatorChunkRecords + len(a.tail.slots) + len(a.udpOrder)
}

// TakeClassifiedRecords consumes the accumulator directly into independently
// owned, exact-capacity buckets, preserving TakeRecords then ClassifyRecords
// order. All scan workers must have finished before the completed syslog cache
// is supplied. A nil cache preserves existing flags. The accumulator must not
// be used afterward.
func (a *Accumulator) TakeClassifiedRecords(fleet FleetSet, cache *SyslogCache) BucketedRecords {
	a.summary.seen = nil
	a.seenSYNs = nil // Release retry keys before allocating destination buckets.
	counts := make(map[Bucket]int)
	count := func(r Record) {
		if bucket, ok := Classify(r, fleet); ok {
			counts[bucket]++
		}
	}
	for _, chunk := range a.tcpChunks {
		for i := range chunk.slots {
			count(chunk.recordAt(i))
		}
	}
	for i := range a.tail.slots {
		count(a.tail.recordAt(i))
	}
	for _, key := range a.udpOrder {
		count(a.udpRecords[key])
	}
	buckets := make(BucketedRecords, len(counts))
	for bucket, n := range counts {
		buckets[bucket] = make([]Record, 0, n)
	}
	appendRecord := func(r Record) {
		if r.Protocol == ProtocolUDP && cache != nil {
			r.SyslogQualified = cache.Known(r.DstAddr(), r.DstPort)
		}
		if bucket, ok := Classify(r, fleet); ok {
			buckets[bucket] = append(buckets[bucket], r)
		}
	}
	for i := range a.tcpChunks {
		for j := range a.tcpChunks[i].slots {
			appendRecord(a.tcpChunks[i].recordAt(j))
		}
		a.tcpChunks[i] = tcpChunk{}
	}
	a.tcpChunks = nil
	for i := range a.tail.slots {
		appendRecord(a.tail.recordAt(i))
	}
	a.tail = tcpChunk{}
	for _, key := range a.udpOrder {
		appendRecord(a.udpRecords[key])
	}
	a.udpRecords = nil
	a.udpOrder = nil
	return buckets
}
