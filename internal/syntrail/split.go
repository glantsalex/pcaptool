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
