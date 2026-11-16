package dns

import "bytes"

// transactionTieLess gives equal-time name evidence a stable order without
// consulting mutable correlation fields. Exact timed SNI duplicates have
// already collapsed to the lexicographically smallest capture basename.
func transactionTieLess(a, b *DNSTransaction) bool {
	if a.DNSName != b.DNSName {
		return a.DNSName < b.DNSName
	}
	if c := bytes.Compare(a.IssuerIP, b.IssuerIP); c != 0 {
		return c < 0
	}
	if a.NameEvidence != b.NameEvidence {
		return a.NameEvidence < b.NameEvidence
	}
	if len(a.ResolvedIPs) > 0 && len(b.ResolvedIPs) > 0 {
		if c := bytes.Compare(a.ResolvedIPs[0], b.ResolvedIPs[0]); c != 0 {
			return c < 0
		}
	}
	if len(a.ResolvedIPs) != len(b.ResolvedIPs) {
		return len(a.ResolvedIPs) < len(b.ResolvedIPs)
	}
	var ap, bp uint16
	if a.DestinationPort != nil {
		ap = *a.DestinationPort
	}
	if b.DestinationPort != nil {
		bp = *b.DestinationPort
	}
	if ap != bp {
		return ap < bp
	}
	return a.PCAPFile < b.PCAPFile
}
