package dns

import "sort"

// IPDNSAppendAuditRecord describes provenance for one newly appended DNS,IP pair.
type IPDNSAppendAuditRecord struct {
	DNS        string
	IP         string
	Evidence   string
	ObservedAt string
	IssuerIP   string
	ResolverIP string
	Protocol   string
	Port       uint16
	PCAPFile   string
}

// BuildIPDNSAppendAuditRecords returns earliest strong packet-backed provenance
// for each newly appended DNS,IP pair.
func BuildIPDNSAppendAuditRecords(txs []*DNSTransaction, pairs []IPDNSPair) []IPDNSAppendAuditRecord {
	if len(pairs) == 0 {
		return nil
	}

	type pairKey struct {
		ip  string
		dns string
	}

	want := make(map[pairKey]struct{}, len(pairs))
	for _, p := range pairs {
		ip, ok := canonicalIPv4String(p.IP)
		if !ok {
			continue
		}
		dns := canonicalDNSName(p.DNS)
		if dns == "" {
			continue
		}
		want[pairKey{ip: ip, dns: dns}] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}

	type candidate struct {
		ts  int64
		rec IPDNSAppendAuditRecord
	}

	best := make(map[pairKey]candidate, len(want))
	for _, tx := range txs {
		if tx == nil || tx.DNSName == "" || len(tx.ResolvedIPs) == 0 {
			continue
		}

		dnsName := canonicalDNSName(tx.DNSName)
		if dnsName == "" {
			continue
		}

		issuerIP := ""
		if tx.IssuerIP != nil {
			issuerIP = tx.IssuerIP.String()
		}
		resolverIP := ""
		if tx.ResolverIP != nil {
			if ip4 := tx.ResolverIP.To4(); ip4 != nil {
				resolverIP = ip4.String()
			} else {
				resolverIP = tx.ResolverIP.String()
			}
		}
		port := uint16(0)
		if tx.DestinationPort != nil {
			port = *tx.DestinationPort
		}
		proto := string(tx.ProtocolL4)
		observedAt := ""
		if !tx.RequestTime.IsZero() {
			observedAt = tx.RequestTime.UTC().Format("2006-01-02 15:04:05.000000000Z07:00")
		}

		for _, ip := range tx.ResolvedIPs {
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			ipStr := ip4.String()
			ev := tx.NameEvidence
			if tx.ResolvedIPEvidence != nil {
				if e, ok := tx.ResolvedIPEvidence[ipStr]; ok {
					ev = e
				}
			}
			if ev&(EvDNSAnswer|EvObservedConn) != (EvDNSAnswer | EvObservedConn) {
				continue
			}

			k := pairKey{ip: ipStr, dns: dnsName}
			if _, ok := want[k]; !ok {
				continue
			}

			rec := IPDNSAppendAuditRecord{
				DNS:        dnsName,
				IP:         ipStr,
				Evidence:   EvidenceString(ev),
				ObservedAt: observedAt,
				IssuerIP:   issuerIP,
				ResolverIP: resolverIP,
				Protocol:   proto,
				Port:       port,
				PCAPFile:   tx.PCAPFile,
			}
			ts := tx.RequestTime.UTC().UnixNano()
			cur, ok := best[k]
			if !ok || ts < cur.ts || (ts == cur.ts && rec.PCAPFile < cur.rec.PCAPFile) {
				best[k] = candidate{ts: ts, rec: rec}
			}
		}
	}

	out := make([]IPDNSAppendAuditRecord, 0, len(pairs))
	for _, p := range pairs {
		ip, ok := canonicalIPv4String(p.IP)
		if !ok {
			continue
		}
		dns := canonicalDNSName(p.DNS)
		if dns == "" {
			continue
		}
		k := pairKey{ip: ip, dns: dns}
		if c, ok := best[k]; ok {
			out = append(out, c.rec)
			continue
		}
		out = append(out, IPDNSAppendAuditRecord{
			DNS: dns,
			IP:  ip,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt == "" && out[j].ObservedAt != "" {
			return false
		}
		if out[i].ObservedAt != "" && out[j].ObservedAt == "" {
			return true
		}
		if out[i].ObservedAt != out[j].ObservedAt {
			return out[i].ObservedAt < out[j].ObservedAt
		}
		if out[i].DNS != out[j].DNS {
			return out[i].DNS < out[j].DNS
		}
		return out[i].IP < out[j].IP
	})

	return out
}
