package dns

import "bytes"

// transactionTieLess gives equal-time name evidence a stable order without
// consulting mutable correlation fields. Exact timed SNI duplicates have
// already collapsed to the lexicographically smallest capture basename.
func transactionTieLess(hostnames *Hostnames, a, b *DNSTransaction) bool {
	if a.DNSNameID != b.DNSNameID {
		return hostnames.name(a.DNSNameID) < hostnames.name(b.DNSNameID)
	}
	if c := bytes.Compare(a.issuerIP(), b.issuerIP()); c != 0 {
		return c < 0
	}
	if a.NameEvidence != b.NameEvidence {
		return a.NameEvidence < b.NameEvidence
	}
	if a.resolvedIPLen() > 0 && b.resolvedIPLen() > 0 {
		if c := a.resolvedIPAt(0).compare(b.resolvedIPAt(0)); c != 0 {
			return c < 0
		}
	}
	if a.resolvedIPLen() != b.resolvedIPLen() {
		return a.resolvedIPLen() < b.resolvedIPLen()
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
