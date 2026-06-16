package syntrail

// SplitFleetToNonFleetByDestinationLocality separates fleet-to-non-fleet records
// by whether their destination IP is private/local.
func SplitFleetToNonFleetByDestinationLocality(records []Record) (public []Record, privateNonFleet []Record) {
	public = make([]Record, 0, len(records))
	privateNonFleet = make([]Record, 0, len(records))

	for _, record := range records {
		if isLocalIPv4(record.DstIP) {
			privateNonFleet = append(privateNonFleet, record)
			continue
		}
		public = append(public, record)
	}

	return public, privateNonFleet
}
