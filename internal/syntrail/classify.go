package syntrail

// Classify assigns r to a SYN trail bucket.
func Classify(r Record, fleet FleetSet) (Bucket, bool) {
	if r.DstPort == 0 || !r.SrcIP.Is4() || !r.DstIP.Is4() {
		return "", false
	}
	if !isLocalIPv4(r.SrcIP) {
		return "", false
	}

	srcInFleet := fleet.Contains(r.SrcIP)
	dstInFleet := fleet.Contains(r.DstIP)

	switch {
	case srcInFleet && !dstInFleet:
		return BucketFleetToNonFleet, true
	case srcInFleet && dstInFleet:
		return BucketFleetToFleet, true
	case isLocalIPv4(r.SrcIP) && !srcInFleet && dstInFleet:
		return BucketPrivateNonFleetToFleet, true
	default:
		return "", false
	}
}

// ClassifyRecords groups records into SYN trail buckets, discarding unclassified records.
func ClassifyRecords(records []Record, fleet FleetSet) BucketedRecords {
	bucketed := make(BucketedRecords)
	for _, record := range records {
		bucket, ok := Classify(record, fleet)
		if !ok {
			continue
		}
		bucketed[bucket] = append(bucketed[bucket], record)
	}
	return bucketed
}
