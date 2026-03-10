// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

// TopologyEntry is one unique row in network-topology-matrix.txt.
//
// Uniqueness invariant (global):
//
//	Issuer | Destination IP | DNS Name | Protocol | Port
type TopologyEntry struct {
	IssuerIP      string
	DestinationIP string
	DNSName       string
	DNSSource     string // e.g. dns+synack, sni+synack, active+synack, csv+synack
	Protocol      string // "tcp" or "udp"
	Port          uint16
	ObservedAt    time.Time
}

// TopologyBuildOptions controls how strictly edges are matched back to DNS txs.
type TopologyBuildOptions struct {
	// MaxDNSAge limits how far back we look for DNS txs for a given edge timestamp.
	// Zero disables the time limit.
	MaxDNSAge time.Duration

	// SortOutput controls the final presentation order.
	// When true, output is sorted for readability/diffs.
	// When false, issuers keep first-seen order and rows within each issuer keep
	// first discovery order.
	SortOutput bool
}

func DefaultTopologyBuildOptions() TopologyBuildOptions {
	return TopologyBuildOptions{
		// Conservative default: reduce shared-IP historical bleed while keeping
		// enough headroom for normal DNS->connect delays.
		MaxDNSAge:  2 * time.Minute,
		SortOutput: true,
	}
}

// BuildNetworkTopologyMatrixEntries joins connectivity edges with DNS/SNI attribution.
func BuildNetworkTopologyMatrixEntries(
	txs []*DNSTransaction,
	edges []connectivity.Edge,
	issuerLabel func(issuerIP string, ts time.Time) string,
	ipToDNS map[string][]string, // last-resort attribution (CSV)
) []TopologyEntry {
	return BuildNetworkTopologyMatrixEntriesWithOptions(
		txs,
		edges,
		issuerLabel,
		ipToDNS,
		DefaultTopologyBuildOptions(),
	)
}

// BuildNetworkTopologyMatrixEntriesWithOptions joins connectivity edges with DNS/SNI
// attribution using conservative time-scoped matching.
func BuildNetworkTopologyMatrixEntriesWithOptions(
	txs []*DNSTransaction,
	edges []connectivity.Edge,
	issuerLabel func(issuerIP string, ts time.Time) string,
	ipToDNS map[string][]string, // last-resort attribution (CSV)
	opt TopologyBuildOptions,
) []TopologyEntry {

	if opt.MaxDNSAge < 0 {
		opt.MaxDNSAge = 0
	}

	normalize := func(name string) string {
		return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
	}

	// Canonicalize IPv4 string (trim + parse). Returns canonical "a.b.c.d".
	canonV4 := func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		ip := net.ParseIP(s)
		if ip == nil {
			return "", false
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return "", false
		}
		return ip4.String(), true
	}

	// ------------------------------------------------------------
	// Build resolver-IP set (issuer-side exclusion)
	// ------------------------------------------------------------
	dnsResolvers := make(map[string]struct{}, 64)
	for _, tx := range txs {
		if tx == nil || tx.ResolverIP == nil {
			continue
		}
		if ip4 := tx.ResolverIP.To4(); ip4 != nil {
			dnsResolvers[ip4.String()] = struct{}{}
		}
	}

	type joinKey struct {
		issuer string
		dstIP  string
	}

	// Raw-IP keyed tx index (not label keyed): (issuerIP,dstIP) -> tx list sorted by RequestTime.
	txByIssuerDst := make(map[joinKey][]*DNSTransaction, 4096)
	for _, tx := range txs {
		if tx == nil || tx.IssuerIP == nil || tx.DNSName == "" {
			continue
		}
		issuerRaw := strings.TrimSpace(tx.IssuerIP.String())
		if issuerRaw == "" {
			continue
		}
		for _, ip := range tx.ResolvedIPs {
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			k := joinKey{issuer: issuerRaw, dstIP: ip4.String()}
			txByIssuerDst[k] = append(txByIssuerDst[k], tx)
		}
	}
	for k := range txByIssuerDst {
		sort.Slice(txByIssuerDst[k], func(i, j int) bool {
			return txByIssuerDst[k][i].RequestTime.Before(txByIssuerDst[k][j].RequestTime)
		})
	}

	edgeProto := func(e connectivity.Edge) L4Proto {
		switch strings.ToLower(strings.TrimSpace(string(e.Protocol))) {
		case "tcp":
			return L4ProtoTCP
		case "udp":
			return L4ProtoUDP
		default:
			return L4ProtoUnknown
		}
	}

	compatScore := func(tx *DNSTransaction, e connectivity.Edge) (int, bool) {
		if tx == nil {
			return 0, false
		}
		score := 0

		// If tx already has protocol selected, require it to match.
		if tx.ProtocolL4 != L4ProtoUnknown {
			p := edgeProto(e)
			if p == L4ProtoUnknown || tx.ProtocolL4 != p {
				return 0, false
			}
			score += 2
		}

		// If tx has a selected destination port, require it to match.
		if tx.DestinationPort != nil && *tx.DestinationPort > 0 {
			if *tx.DestinationPort != e.Port {
				return 0, false
			}
			score += 2
		}

		// Slightly prefer SNI-derived names when present (strong direct signal).
		if tx.NameEvidence&EvSNI != 0 {
			score++
		}

		return score, true
	}

	pickBestTxForEdge := func(bucket []*DNSTransaction, e connectivity.Edge) *DNSTransaction {
		if len(bucket) == 0 {
			return nil
		}

		edgeTS := e.FirstSeen.UTC()
		lo := 0
		hi := len(bucket)

		if !edgeTS.IsZero() {
			// Only txs observed at/before edge first-seen.
			hi = sort.Search(len(bucket), func(i int) bool {
				return bucket[i].RequestTime.After(edgeTS)
			})
			if opt.MaxDNSAge > 0 {
				start := edgeTS.Add(-opt.MaxDNSAge)
				lo = sort.Search(len(bucket), func(i int) bool {
					return !bucket[i].RequestTime.Before(start)
				})
			}
		}

		if lo >= hi {
			return nil
		}

		var (
			best      *DNSTransaction
			bestScore = -1
			bestDT    = time.Duration(1<<63 - 1)
		)

		for i := lo; i < hi; i++ {
			tx := bucket[i]
			score, ok := compatScore(tx, e)
			if !ok {
				continue
			}

			dt := time.Duration(0)
			if !edgeTS.IsZero() {
				if tx.RequestTime.After(edgeTS) {
					continue
				}
				dt = edgeTS.Sub(tx.RequestTime)
			}

			if best == nil ||
				score > bestScore ||
				(score == bestScore && dt < bestDT) ||
				(score == bestScore && dt == bestDT && tx.RequestTime.After(best.RequestTime)) {
				best = tx
				bestScore = score
				bestDT = dt
			}
		}

		return best
	}

	seen := make(map[string]int, len(edges)*2)
	out := make([]TopologyEntry, 0, len(edges)*2)

	sourceRank := func(src string) int {
		s := strings.ToLower(strings.TrimSpace(src))
		switch s {
		case "dns+synack", "dns+conn+synack",
			"sni+synack", "sni+conn+synack",
			"active+synack", "active+conn+synack":
			return 30
		case "csv+conn", "csv+mid":
			return 20
		case "mid-session":
			return 10
		case "":
			return 0
		default:
			// Any non-empty evidence-like source that's not explicitly ranked.
			return 15
		}
	}

	for _, e := range edges {
		if strings.TrimSpace(e.IssuerIP) == "" || strings.TrimSpace(e.DstIP) == "" || e.Port == 0 {
			continue
		}

		issuerRaw := strings.TrimSpace(e.IssuerIP)
		dstRaw := strings.TrimSpace(e.DstIP)

		dstIP, ok := canonV4(dstRaw)
		if !ok {
			continue
		}
		dstParsed := net.ParseIP(dstIP)
		if dstParsed == nil {
			continue
		}

		// --------------------------------------------------------
		// HARD EXCLUSIONS — DNS server responses MUST NOT appear
		// --------------------------------------------------------

		// Exclude DNS protocol traffic (transport)
		if e.Port == 53 || e.Port == 853 || e.Port == 5353 {
			continue
		}

		// Exclude edges where issuer is a DNS resolver
		if _, ok := dnsResolvers[issuerRaw]; ok {
			continue
		}

		issuer := issuerRaw
		if issuerLabel != nil {
			if lbl := issuerLabel(issuerRaw, e.FirstSeen); lbl != "" {
				issuer = strings.TrimSpace(lbl)
			}
		}

		proto := string(e.Protocol)

		emit := func(dnsName, src string) {
			// IMPORTANT: use canonical dst IP in key and output.
			key := issuer + "|" + dstIP + "|" + dnsName + "|" + proto + "|" + itoa16(e.Port)
			if idx, ok := seen[key]; ok {
				// Keep one row per key, but prefer stronger attribution source.
				if sourceRank(src) > sourceRank(out[idx].DNSSource) {
					out[idx].DNSSource = src
					out[idx].ObservedAt = e.FirstSeen.UTC()
				}
				return
			}
			seen[key] = len(out)
			out = append(out, TopologyEntry{
				IssuerIP:      issuer,
				DestinationIP: dstIP,
				DNSName:       dnsName,
				DNSSource:     src,
				Protocol:      proto,
				Port:          e.Port,
				ObservedAt:    e.FirstSeen.UTC(),
			})
		}

		// --------------------------------------------------------
		// Never infer/attach DNS for private destination IPs.
		// --------------------------------------------------------
		if dstParsed.IsPrivate() {
			emit("", "")
			continue
		}

		// Canonical dstIP is used for map keys.
		bestTx := pickBestTxForEdge(txByIssuerDst[joinKey{issuer: issuerRaw, dstIP: dstIP}], e)
		if bestTx == nil {
			issuerIP := net.ParseIP(issuerRaw)

			// --------------------------------------------------------
			// MID-SESSION PRIVATE → PUBLIC FALLBACK
			// --------------------------------------------------------
			if issuerIP != nil && issuerIP.IsPrivate() && !dstParsed.IsPrivate() {
				// Try CSV attribution first.
				// For mid-session rows, keep full FQDN when CSV has exactly one name.
				if suf, ok := csvNameForIP(ipToDNS, dstIP, true); ok {
					emit(suf, "csv+mid")
				} else {
					emit("", "mid-session")
				}
				continue
			}

			// --------------------------------------------------------
			// Normal CSV fallback (non mid-session cases)
			// --------------------------------------------------------
			if suf, ok := csvNameForIP(ipToDNS, dstIP, false); ok {
				emit(suf, "csv+conn")
				continue
			}

			emit("", "")
			continue
		}
		dnsName := normalize(bestTx.DNSName)
		src := ""
		if dnsName != "" {
			ev := bestTx.NameEvidence
			if bestTx.ResolvedIPEvidence != nil {
				ev |= bestTx.ResolvedIPEvidence[dstIP]
			}
			if ev != EvNone {
				ev |= EvObservedConn
				src = EvidenceString(ev)
			}
		}
		emit(dnsName, src)
	}

	// ------------------------------------------------------------
	// FINAL CSV CHECK (mid-session capture hardening)
	//
	// Before emitting to a file, for each PUBLIC dst IP that is still unresolved,
	// consult CSV (ipToDNS) one more time.
	//
	// - Applies only when DNSName is empty and dst IP is public IPv4.
	// - Never applies to private dst IPs.
	// - Does NOT overwrite existing DNS evidence.
	// - If CSV resolves:
	//   - exactly one DNS name for IP -> full FQDN and DNSSource "csv+conn".
	//   - more than one DNS name for IP -> skip CSV fallback (ambiguous mapping).
	// - If CSV does not resolve, KEEP the unresolved row (do not drop it).
	// ------------------------------------------------------------
	if ipToDNS != nil && len(out) > 0 {
		seen2 := make(map[string]struct{}, len(out)*2)
		out2 := make([]TopologyEntry, 0, len(out)*2)

		mk := func(e TopologyEntry) string {
			return e.IssuerIP + "|" + e.DestinationIP + "|" + e.DNSName + "|" + e.Protocol + "|" + itoa16(e.Port)
		}

		for _, row := range out {
			// Normalize destination IP again defensively.
			dstIP, ok := canonV4(row.DestinationIP)
			if ok {
				row.DestinationIP = dstIP
			}

			// Keep resolved entries as-is
			if row.DNSName != "" {
				k := mk(row)
				if _, ok := seen2[k]; ok {
					continue
				}
				seen2[k] = struct{}{}
				out2 = append(out2, row)
				continue
			}

			dst := net.ParseIP(row.DestinationIP)
			if dst == nil || dst.To4() == nil || dst.IsPrivate() {
				// private or invalid -> never infer DNS
				k := mk(row)
				if _, ok := seen2[k]; ok {
					continue
				}
				seen2[k] = struct{}{}
				out2 = append(out2, row)
				continue
			}

			if suf, ok := csvNameForIP(ipToDNS, row.DestinationIP, false); ok {
				row.DNSName = suf
				row.DNSSource = "csv+conn"
			}

			// IMPORTANT: keep the row even if CSV did not resolve.
			k := mk(row)
			if _, ok := seen2[k]; ok {
				continue
			}
			seen2[k] = struct{}{}
			out2 = append(out2, row)
		}

		out = out2
	}

	// ------------------------------------------------------------
	// Suppress unresolved rows when any DNS-attributed row exists for
	// the same issuer|dst|proto|port tuple.
	//
	// This intentionally treats:
	//   35.190.88.7 + DNS
	//   35.190.88.7 + mid-session (blank DNS)
	// as the same destination endpoint and keeps only the DNS-attributed row.
	// ------------------------------------------------------------
	if len(out) > 0 {
		type k struct {
			issuer, dst, proto string
			port               uint16
		}

		hasResolved := make(map[k]struct{}, len(out))
		for _, row := range out {
			if row.DNSName == "" {
				continue
			}
			key := k{
				issuer: row.IssuerIP,
				dst:    row.DestinationIP,
				proto:  row.Protocol,
				port:   row.Port,
			}
			hasResolved[key] = struct{}{}
		}

		if len(hasResolved) > 0 {
			out2 := make([]TopologyEntry, 0, len(out))
			for _, row := range out {
				if row.DNSName == "" {
					key := k{
						issuer: row.IssuerIP,
						dst:    row.DestinationIP,
						proto:  row.Protocol,
						port:   row.Port,
					}
					if _, ok := hasResolved[key]; ok {
						continue
					}
				}
				out2 = append(out2, row)
			}
			out = out2
		}
	}

	// ------------------------------------------------------------
	// Prefer DNS-observed attribution over CSV fallback.
	//
	// If a tuple has strong DNS evidence:
	//   - dns+synack
	//   - dns+conn+synack
	// then csv+mid/csv+conn rows are handled as follows:
	//   - issuer|public-dst|proto|port matches exactly, OR
	//   - issuer|public-dst|proto matches and CSV DNS conflicts with strong DNS names.
	//
	// Exact tuple matches are dropped (duplicate attribution for same endpoint).
	// Cross-port conflicts are downgraded to unresolved (keep endpoint visibility).
	// ------------------------------------------------------------
	if len(out) > 0 {
		type key4 struct {
			issuer, dst, proto string
			port               uint16
		}
		type key3 struct {
			issuer, dst, proto string
		}

		isPreferredDNS := func(src string) bool {
			s := strings.ToLower(strings.TrimSpace(src))
			return s == "dns+synack" || s == "dns+conn+synack"
		}

		isCSVFallback := func(src string) bool {
			s := strings.ToLower(strings.TrimSpace(src))
			return s == "csv+mid" || s == "csv+conn"
		}

		normalizeName := func(s string) string {
			return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		}

		preferredByTuple4 := make(map[key4]struct{}, len(out))
		strongNamesByTuple3 := make(map[key3]map[string]struct{}, len(out))
		for _, row := range out {
			if row.DNSName == "" || !isPreferredDNS(row.DNSSource) {
				continue
			}
			dst := net.ParseIP(row.DestinationIP)
			if dst == nil || dst.To4() == nil || dst.IsPrivate() {
				continue
			}
			k4 := key4{
				issuer: row.IssuerIP,
				dst:    row.DestinationIP,
				proto:  row.Protocol,
				port:   row.Port,
			}
			preferredByTuple4[k4] = struct{}{}

			k3 := key3{
				issuer: row.IssuerIP,
				dst:    row.DestinationIP,
				proto:  row.Protocol,
			}
			names := strongNamesByTuple3[k3]
			if names == nil {
				names = make(map[string]struct{}, 2)
				strongNamesByTuple3[k3] = names
			}
			if n := normalizeName(row.DNSName); n != "" {
				names[n] = struct{}{}
			}
		}

		if len(preferredByTuple4) > 0 || len(strongNamesByTuple3) > 0 {
			out2 := make([]TopologyEntry, 0, len(out))
			for _, row := range out {
				if row.DNSName != "" && isCSVFallback(row.DNSSource) {
					dst := net.ParseIP(row.DestinationIP)
					if dst != nil && dst.To4() != nil && !dst.IsPrivate() {
						k4 := key4{
							issuer: row.IssuerIP,
							dst:    row.DestinationIP,
							proto:  row.Protocol,
							port:   row.Port,
						}
						if _, ok := preferredByTuple4[k4]; ok {
							continue
						}

						// Cross-port conflict handling:
						// if strong DNS exists for same issuer|dst|proto and CSV DNS differs,
						// downgrade CSV row to unresolved to avoid cross-port contamination
						// from fallback tables while preserving endpoint visibility.
						k3 := key3{
							issuer: row.IssuerIP,
							dst:    row.DestinationIP,
							proto:  row.Protocol,
						}
						if strongNames := strongNamesByTuple3[k3]; len(strongNames) > 0 {
							if _, ok := strongNames[normalizeName(row.DNSName)]; !ok {
								row.DNSName = ""
								if strings.EqualFold(strings.TrimSpace(row.DNSSource), "csv+mid") {
									row.DNSSource = "mid-session"
								} else {
									row.DNSSource = ""
								}
							}
						}
					}
				}
				out2 = append(out2, row)
			}
			out = out2
		}
	}

	// ------------------------------------------------------------
	// Run-local peer completion for unresolved rows.
	//
	// If a PUBLIC (dstIP, proto, port) tuple has a unique strong resolved DNS
	// name elsewhere in the same run, use it to fill unresolved rows for that
	// exact endpoint tuple across issuers.
	//
	// Donor priority:
	//   1) direct donor:  dns+synack / sni+synack        -> peer+ipport
	//   2) inferred donor: dns+conn+synack               -> peer+ipport+conn
	//
	// CSV/active/mid-session rows never act as donors. Ambiguous tuples (more than
	// one unique donor name in the same tier) are left unresolved.
	// ------------------------------------------------------------
	if len(out) > 0 {
		type peerKey struct {
			dst, proto string
			port       uint16
		}
		type donorSet struct {
			directNames   map[string]string
			inferredNames map[string]string
		}

		isDirectPeerDonor := func(src string) bool {
			s := strings.ToLower(strings.TrimSpace(src))
			return s == "dns+synack" || s == "sni+synack"
		}
		isInferredPeerDonor := func(src string) bool {
			s := strings.ToLower(strings.TrimSpace(src))
			return s == "dns+conn+synack"
		}

		donorsByTuple := make(map[peerKey]*donorSet, len(out))
		for _, row := range out {
			if strings.TrimSpace(row.DNSName) == "" {
				continue
			}
			dst := net.ParseIP(row.DestinationIP)
			if dst == nil || dst.To4() == nil || dst.IsPrivate() {
				continue
			}

			pk := peerKey{
				dst:   row.DestinationIP,
				proto: row.Protocol,
				port:  row.Port,
			}
			ds := donorsByTuple[pk]
			if ds == nil {
				ds = &donorSet{
					directNames:   make(map[string]string, 1),
					inferredNames: make(map[string]string, 1),
				}
				donorsByTuple[pk] = ds
			}

			name := normalize(row.DNSName)
			if name == "" {
				continue
			}
			switch {
			case isDirectPeerDonor(row.DNSSource):
				ds.directNames[name] = row.DNSName
			case isInferredPeerDonor(row.DNSSource):
				ds.inferredNames[name] = row.DNSName
			}
		}

		for i := range out {
			row := &out[i]
			if strings.TrimSpace(row.DNSName) != "" {
				continue
			}
			dst := net.ParseIP(row.DestinationIP)
			if dst == nil || dst.To4() == nil || dst.IsPrivate() {
				continue
			}

			pk := peerKey{
				dst:   row.DestinationIP,
				proto: row.Protocol,
				port:  row.Port,
			}
			ds := donorsByTuple[pk]
			if ds == nil {
				continue
			}

			if len(ds.directNames) == 1 {
				for _, orig := range ds.directNames {
					row.DNSName = orig
					row.DNSSource = "peer+ipport"
				}
				continue
			}
			if len(ds.directNames) == 0 && len(ds.inferredNames) == 1 {
				for _, orig := range ds.inferredNames {
					row.DNSName = orig
					row.DNSSource = "peer+ipport+conn"
				}
			}
		}
	}

	if !opt.SortOutput {
		issuerFirst := make(map[string]int, len(out))
		nextIssuer := 0
		for _, row := range out {
			if _, ok := issuerFirst[row.IssuerIP]; ok {
				continue
			}
			issuerFirst[row.IssuerIP] = nextIssuer
			nextIssuer++
		}
		sort.SliceStable(out, func(i, j int) bool {
			return issuerFirst[out[i].IssuerIP] < issuerFirst[out[j].IssuerIP]
		})
		return out
	}

	// Deterministic ordering for diffs.
	// Issuers are ranked by number of unique destination endpoints
	// (destination IP + protocol + port) desc.
	// Within each issuer, rows are grouped by DNS name first, then destination IP.
	// Empty DNS names (unresolved) are pushed to the end.
	issuerEndpointCount := endpointCountByIssuer(out)

	sort.Slice(out, func(i, j int) bool {
		ci := issuerEndpointCount[out[i].IssuerIP]
		cj := issuerEndpointCount[out[j].IssuerIP]
		if ci != cj {
			return ci > cj
		}

		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}

		// Within one issuer: keep private destination IPv4s at the end.
		pi := isPrivateIPv4Destination(out[i].DestinationIP)
		pj := isPrivateIPv4Destination(out[j].DestinationIP)
		if pi != pj {
			return !pi && pj
		}

		ai, aj := out[i].DNSName, out[j].DNSName
		if ai == "" && aj != "" {
			return false
		}
		if ai != "" && aj == "" {
			return true
		}
		if ai != aj {
			return ai < aj
		}

		if out[i].DestinationIP != out[j].DestinationIP {
			return out[i].DestinationIP < out[j].DestinationIP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})

	return out
}

// SquashNetworkTopologyShort keeps issuer|dst|proto|port uniqueness.
func SquashNetworkTopologyShort(in []TopologyEntry) []TopologyEntry {
	return SquashNetworkTopologyShortWithOptions(in, true)
}

func SquashNetworkTopologyShortWithOptions(in []TopologyEntry, sortOutput bool) []TopologyEntry {
	type k struct {
		i, d, p string
		port    uint16
	}
	best := make(map[k]TopologyEntry, len(in))
	order := make([]k, 0, len(in))

	for _, e := range in {
		key := k{e.IssuerIP, e.DestinationIP, e.Protocol, e.Port}
		cur, ok := best[key]
		if !ok {
			order = append(order, key)
		}
		if !ok || (cur.DNSName == "" && e.DNSName != "") || (e.DNSName < cur.DNSName) {
			best[key] = e
		}
	}

	out := make([]TopologyEntry, 0, len(best))
	for _, key := range order {
		out = append(out, best[key])
	}

	if !sortOutput {
		issuerFirst := make(map[string]int, len(out))
		nextIssuer := 0
		for _, row := range out {
			if _, ok := issuerFirst[row.IssuerIP]; ok {
				continue
			}
			issuerFirst[row.IssuerIP] = nextIssuer
			nextIssuer++
		}
		sort.SliceStable(out, func(i, j int) bool {
			return issuerFirst[out[i].IssuerIP] < issuerFirst[out[j].IssuerIP]
		})
		return out
	}

	issuerEndpointCount := endpointCountByIssuer(out)

	sort.Slice(out, func(i, j int) bool {
		ci := issuerEndpointCount[out[i].IssuerIP]
		cj := issuerEndpointCount[out[j].IssuerIP]
		if ci != cj {
			return ci > cj
		}
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		pi := isPrivateIPv4Destination(out[i].DestinationIP)
		pj := isPrivateIPv4Destination(out[j].DestinationIP)
		if pi != pj {
			return !pi && pj
		}
		if out[i].DestinationIP != out[j].DestinationIP {
			return out[i].DestinationIP < out[j].DestinationIP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func endpointCountByIssuer(rows []TopologyEntry) map[string]int {
	type endpointKey struct {
		dst   string
		proto string
		port  uint16
	}

	perIssuer := make(map[string]map[endpointKey]struct{}, len(rows))
	for _, r := range rows {
		if r.IssuerIP == "" || r.DestinationIP == "" {
			continue
		}
		m := perIssuer[r.IssuerIP]
		if m == nil {
			m = make(map[endpointKey]struct{}, 16)
			perIssuer[r.IssuerIP] = m
		}
		m[endpointKey{
			dst:   r.DestinationIP,
			proto: r.Protocol,
			port:  r.Port,
		}] = struct{}{}
	}

	out := make(map[string]int, len(perIssuer))
	for issuer, endpoints := range perIssuer {
		out[issuer] = len(endpoints)
	}
	return out
}

func isPrivateIPv4Destination(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4.IsPrivate()
}

func itoa16(v uint16) string {
	if v == 0 {
		return "0"
	}
	buf := [5]byte{}
	i := len(buf)
	x := int(v)
	for x > 0 {
		i--
		buf[i] = byte('0' + (x % 10))
		x /= 10
	}
	return string(buf[i:])
}

func csvNameForIP(ipToDNS map[string][]string, ipStr string, _ bool) (string, bool) {
	if ipToDNS == nil {
		return "", false
	}

	raw := strings.TrimSpace(ipStr)

	// Canonicalize input IPv4 if possible
	if pip := net.ParseIP(raw); pip != nil {
		if ip4 := pip.To4(); ip4 != nil {
			raw = ip4.String()
		}
	}

	lst := ipToDNS[raw]
	if len(lst) == 0 {
		// Defensive: try trimmed-map-key match (handles accidental whitespace in CSV keys)
		for k, v := range ipToDNS {
			if strings.TrimSpace(k) == raw && len(v) > 0 {
				lst = v
				break
			}
		}
	}
	if len(lst) == 0 {
		return "", false
	}

	normalizeDNS := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ".")
		s = strings.ToLower(s)
		return s
	}

	names := make([]string, 0, len(lst))
	seenNames := make(map[string]struct{}, len(lst))
	for _, n := range lst {
		n = normalizeDNS(n)
		if n == "" {
			continue
		}
		if _, ok := seenNames[n]; ok {
			continue
		}
		seenNames[n] = struct{}{}
		names = append(names, n)
	}
	if len(names) == 0 {
		return "", false
	}

	// CSV fallback is allowed only for unambiguous one-to-one IP->DNS mappings.
	if len(names) > 1 {
		return "", false
	}

	// Single-name case: always keep full FQDN.
	return names[0], true
}
