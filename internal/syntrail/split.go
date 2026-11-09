package syntrail

// SplitFleetToNonFleetByDestinationLocality separates fleet-to-non-fleet records
// by whether their destination IP is private/local.
func SplitFleetToNonFleetByDestinationLocality(records []Record) (public []Record, privateNonFleet []Record) {
	// Keep independent output storage without reserving the entire corpus for
	// both partitions. Callers frequently need only one partition at a time.
	privateCount := 0
	for _, record := range records {
		if isLocalIPv4(record.DstIP) {
			privateCount++
		}
	}
	public = make([]Record, 0, len(records)-privateCount)
	privateNonFleet = make([]Record, 0, privateCount)

	for _, record := range records {
		if isLocalIPv4(record.DstIP) {
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
		if isLocalIPv4(record.DstIP) == private {
			count++
		}
	}
	selected := make([]Record, 0, count)
	for _, record := range records {
		if isLocalIPv4(record.DstIP) == private {
			selected = append(selected, record)
		}
	}
	return selected
}
