package syntrail

// SplitFleetToNonFleetByDestinationLocality separates fleet-to-non-fleet records
// by whether their destination IP is private/local.
func SplitFleetToNonFleetByDestinationLocality(records []Record) (public []Record, privateNonFleet []Record) {
	// Keep independent output storage without reserving the entire corpus for
	// both partitions. Callers frequently need only one partition at a time.
	privateCount := 0
	for _, record := range records {
		if isLocalIPv4(record.DstAddr()) {
			privateCount++
		}
	}
	public = make([]Record, 0, len(records)-privateCount)
	privateNonFleet = make([]Record, 0, privateCount)

	for _, record := range records {
		if isLocalIPv4(record.DstAddr()) {
			privateNonFleet = append(privateNonFleet, record)
			continue
		}
		public = append(public, record)
	}

	return public, privateNonFleet
}

// SelectFleetToNonFleetByDestinationLocality returns only the requested partition
// (private=true for local destinations). The result has independent, exact-sized
// storage, preserves input order, and is non-nil even when empty. Callers may
// compact or sort it without changing the source records or another artifact.
func SelectFleetToNonFleetByDestinationLocality(records []Record, private bool) []Record {
	count := 0
	for _, record := range records {
		if isLocalIPv4(record.DstAddr()) == private {
			count++
		}
	}
	selected := make([]Record, 0, count)
	for _, record := range records {
		if isLocalIPv4(record.DstAddr()) == private {
			selected = append(selected, record)
		}
	}
	return selected
}

// SelectPublicServerSummary returns one representative per normalized public
// destination/protocol/port tuple after keep accepts the observation. Filtering
// precedes deduplication because acceptance may depend on the source. The input
// is borrowed read-only; result storage grows with distinct endpoints only.
func SelectPublicServerSummary(records []Record, keep func(Record) bool) []Record {
	seen := make(map[ServerTuple]struct{})
	selected := make([]Record, 0)
	for _, record := range records {
		if isLocalIPv4(record.DstAddr()) || (keep != nil && !keep(record)) {
			continue
		}
		key := ServerTuple{DstIP: record.DstAddr(), DstPort: record.DstPort, Protocol: normalizedProtocol(record.Protocol)}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, record)
	}
	return selected
}
