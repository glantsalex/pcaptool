package dns

import (
	"cmp"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DeviceResolver returns an empty identity for a device outside the selected population.
type DeviceResolver func(netip.Addr, time.Time) string

// captureTime stores UTC wire time without retaining a Location pointer and
// preserves PCAPNG dates outside the signed Unix-nanosecond range.
type captureTime struct {
	sec  int64
	nano int32
}

func wireTime(t time.Time) captureTime { return captureTime{t.Unix(), int32(t.Nanosecond())} }
func (t captureTime) utc() time.Time   { return time.Unix(t.sec, int64(t.nano)).UTC() }
func (t captureTime) compare(u captureTime) int {
	if t.sec != u.sec {
		return cmp.Compare(t.sec, u.sec)
	}
	return cmp.Compare(t.nano, u.nano)
}

type nameKey struct{ device, name string }
type answerValue struct {
	complete bool
	ip       netip.Addr
	chain    string
}
type answerSeries struct {
	nameKey
	answerValue
}
type answerEvent struct {
	at captureTime
	answerValue
}
type destinationKey struct {
	device string
	ip     netip.Addr
}
type binding struct {
	start, end  captureTime
	name, chain string
}

// FactCollection spans the DNS and connection passes of a single run. Only
// DNS answer ingestion is concurrent. Prepare freezes the temporal lookup;
// file workers subsequently merge their facts on the ordered coordinator.
type FactCollection struct {
	resolve    DeviceResolver
	sni        bool
	window     time.Duration
	mu         sync.Mutex
	answers    map[answerSeries][]captureTime
	bindings   map[destinationKey][]binding
	resolvers  map[netip.Addr]bool
	unanswered map[string][]*DNSTransaction
	csv        map[string][]string
	facts      factSet
}

// NewFactCollection initializes the device facts for one run.
func NewFactCollection(resolve DeviceResolver, sni bool, window time.Duration) *FactCollection {
	return &FactCollection{resolve: resolve, sni: sni, window: window, answers: make(map[answerSeries][]captureTime), facts: make(factSet)}
}

func (c *FactCollection) resolveWire(raw string, ts time.Time) string {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	return c.resolve(addr.Unmap(), ts)
}

// A series shares the device, name, address and CNAME evidence. Refresh times
// can change which name wins when another file supplies an intervening answer.
func (c *FactCollection) answer(device, name string, ts time.Time, ips []net.IP, cnames []string, complete bool) {
	key := answerSeries{nameKey: nameKey{device, canonicalDNSName(name)}, answerValue: answerValue{complete: complete, chain: strings.Join(cnames, ";")}}
	if key.name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at := wireTime(ts)
	add := func(ip netip.Addr) {
		key.ip = ip
		times := c.answers[key]
		if len(times) == 0 || times[len(times)-1] != at {
			c.answers[key] = append(times, at)
		}
	}
	if len(ips) == 0 && complete {
		add(netip.Addr{})
		return
	}
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
			add(addr)
		}
	}
}

// Prepare builds half-open name-validity intervals from complete observed
// answer sets. A replacement answer invalidates addresses dropped by that name.
func (c *FactCollection) Prepare(txs []*DNSTransaction, csv map[string][]string, infer bool) {
	c.csv = csv
	c.bindings = make(map[destinationKey][]binding)
	c.resolvers = make(map[netip.Addr]bool)
	c.unanswered = make(map[string][]*DNSTransaction)
	for _, tx := range txs {
		if ip, ok := netip.AddrFromSlice(tx.ResolverIP); ok {
			c.resolvers[ip.Unmap()] = true
		}
		if infer && tx.ResolvedIPCount() == 0 && LooksLikeResolvableDNSName(tx.DNSName) {
			c.unanswered[tx.IssuerLabel] = append(c.unanswered[tx.IssuerLabel], tx)
		}
	}
	byName := make(map[nameKey][]answerEvent)
	for k, times := range c.answers {
		for _, at := range times {
			byName[k.nameKey] = append(byName[k.nameKey], answerEvent{at, k.answerValue})
		}
		delete(c.answers, k)
	}
	c.answers = nil
	for key, events := range byName {
		slices.SortFunc(events, func(a, b answerEvent) int { return b.at.compare(a.at) })
		nextComplete := captureTime{sec: math.MaxInt64}
		for len(events) > 0 {
			at := events[0].at
			i := sort.Search(len(events), func(i int) bool { return events[i].at.compare(at) < 0 })
			end := nextComplete
			if c.window > 0 {
				expiry := wireTime(at.utc().Add(c.window).Add(time.Nanosecond))
				if expiry.compare(end) < 0 {
					end = expiry
				}
			}
			for _, e := range events[:i] {
				if e.complete {
					nextComplete = at
				}
				if e.ip.IsValid() {
					k := destinationKey{key.device, e.ip}
					c.bindings[k] = append(c.bindings[k], binding{at, end, key.name, e.chain})
				}
			}
			events = events[i:]
		}
		delete(byName, key)
	}
	for k, bs := range c.bindings {
		c.bindings[k] = nameTimeline(bs)
	}
}

// nameTimeline chooses the most recent still-valid answer. A simultaneous
// conflict contributes no name until it resolves. Coalesce adjacent intervals
// only after considering all captures and competing names.
func nameTimeline(bs []binding) []binding {
	slices.SortFunc(bs, func(a, b binding) int {
		if a.start != b.start {
			return a.start.compare(b.start)
		}
		if a.name != b.name {
			return cmp.Compare(a.name, b.name)
		}
		if a.chain != b.chain {
			return cmp.Compare(a.chain, b.chain)
		}
		return a.end.compare(b.end)
	})
	bs = slices.Compact(bs)
	points := make([]captureTime, 0, 2*len(bs))
	for _, b := range bs {
		points = append(points, b.start, b.end)
	}
	slices.SortFunc(points, captureTime.compare)
	points = slices.Compact(points)
	var out []binding
	var stack [][]binding
	next := 0
	for i, at := range points[:len(points)-1] {
		start := next
		for next < len(bs) && bs[next].start == at {
			next++
		}
		if next > start {
			stack = append(stack, bs[start:next])
		}
		for len(stack) > 0 {
			var winner binding
			haveWinner := false
			for _, b := range stack[len(stack)-1] {
				if b.end.compare(at) <= 0 {
					continue
				}
				if !haveWinner {
					haveWinner = true
					winner = b
				} else if winner.name != b.name {
					winner.name = ""
					winner.end = points[i+1]
					break
				}
			}
			if !haveWinner {
				stack = stack[:len(stack)-1]
				continue
			}
			if winner.name != "" {
				n := len(out)
				if n > 0 && out[n-1].end == at && out[n-1].name == winner.name && out[n-1].chain == winner.chain {
					out[n-1].end = points[i+1]
				} else {
					out = append(out, binding{at, points[i+1], winner.name, winner.chain})
				}
			}
			break
		}
	}
	return out
}

type transportFact struct {
	device string
	dst    netip.Addr
	proto  connectivity.L4Proto
	port   uint16
}
type factKey struct {
	transportFact
	name string
}
type factValue struct {
	first         captureTime
	source, chain string
}

// Most transports have one name. Only a second distinct name needs a map.
type factGroup struct {
	name  string
	value factValue
	other map[string]factValue
}
type factSet map[transportFact]factGroup

func mergeValue(prev, v factValue) factValue {
	if prev == v {
		return prev
	}
	if topologySourceRank(prev.source) > topologySourceRank(v.source) || (topologySourceRank(prev.source) == topologySourceRank(v.source) && prev.source < v.source) {
		v.source = prev.source
	}
	if prev.chain != v.chain {
		parts := splitTopologyCNAMEChain(mergeTopologyCNAMEChain(prev.chain, splitTopologyCNAMEChain(v.chain)))
		slices.Sort(parts)
		v.chain = strings.Join(parts, ";")
	}
	if prev.first.compare(v.first) < 0 {
		v.first = prev.first
	}
	return v
}

func (s factSet) add(k factKey, v factValue) {
	group, ok := s[k.transportFact]
	switch {
	case !ok || (group.name == "" && k.name != "") || (group.value.source == "csv+mid" && topologySourceRank(v.source) > topologySourceRank("csv+mid")):
		s[k.transportFact] = factGroup{name: k.name, value: v}
	case ok && v.source == "csv+mid" && topologySourceRank(group.value.source) > topologySourceRank(v.source):
		return
	case group.name == k.name:
		if merged := mergeValue(group.value, v); merged != group.value {
			group.value = merged
			s[k.transportFact] = group
		}
	case k.name == "":
		// The named contact already supplies the relationship for this tuple.
		return
	default:
		if group.other == nil {
			group.other = make(map[string]factValue)
			s[k.transportFact] = group
		}
		if prev, ok := group.other[k.name]; ok {
			v = mergeValue(prev, v)
			if prev == v {
				return
			}
		}
		group.other[k.name] = v
	}
}

func (s factSet) each(visit func(factKey, factValue)) {
	for t, g := range s {
		visit(factKey{t, g.name}, g.value)
		for name, v := range g.other {
			visit(factKey{t, name}, v)
		}
	}
}

// Len counts distinct completed device/service facts, including additional names.
func (c *FactCollection) Len() int {
	n := len(c.facts)
	for _, g := range c.facts {
		n += len(g.other)
	}
	return n
}

func blockedService(port uint16) bool { return port == 0 || port == 53 || port == 853 || port == 5353 }

// pendingQuery reads the frozen query set. Diagnostic backfills during the
// connection scan cannot change eligibility for other files.
func (c *FactCollection) pendingQuery(device string, ts time.Time) (*DNSTransaction, int) {
	list := c.unanswered[device]
	start := ts.Add(-maxConnDelay)
	lo := sort.Search(len(list), func(i int) bool { return !list[i].RequestTime.Before(start) })
	hi := sort.Search(len(list), func(i int) bool { return list[i].RequestTime.After(ts) })
	if hi == lo+1 {
		return list[lo], 1
	}
	return nil, hi - lo
}

func (c *FactCollection) contact(s factSet, device, wire, dst string, p connectivity.L4Proto, port uint16, ts time.Time, confirmed bool) {
	ip, err := netip.ParseAddr(dst)
	if err != nil || !ip.Is4() || blockedService(port) {
		return
	}
	client, _ := netip.ParseAddr(wire)
	if c.resolvers[client] {
		return
	}
	at := wireTime(ts)
	bs := c.bindings[destinationKey{device, ip}]
	i := sort.Search(len(bs), func(i int) bool { return bs[i].start.compare(at) > 0 })
	name, source, chain := "", "", ""
	if i > 0 && at.compare(bs[i-1].end) < 0 && bs[i-1].name != "" {
		name, source, chain = bs[i-1].name, "dns+synack", bs[i-1].chain
	}
	if name == "" && len(bs) == 0 && confirmed && p == connectivity.ProtoTCP {
		if tx, _ := c.pendingQuery(device, ts); tx != nil {
			if allow, _ := allowConnectionInferredDNSBackfill(tx.DNSName, dst, c.csv); allow {
				name, source = tx.DNSName, "dns+conn+synack"
			}
		}
	}
	if name == "" && !ip.IsPrivate() {
		source = "mid-session"
		if n, ok := csvNameForIP(c.csv, dst, true); ok {
			name, source = n, "csv+mid"
		}
	}
	s.add(factKey{transportFact{device, ip, p, port}, name}, factValue{at, source, chain})
}

func (c *FactCollection) hello(s factSet, pkt gopacket.Packet, exclude map[uint16]struct{}, collector *connectivity.Collector) bool {
	if !c.sni || pkt.Metadata().Truncated {
		return false
	}
	tcp, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok || tcp.SrcPort == 0 || len(tcp.Payload) == 0 {
		return false
	}
	port := uint16(tcp.DstPort)
	if _, blocked := exclude[port]; blocked || blockedService(port) {
		return false
	}
	ip, ok := pkt.NetworkLayer().(*layers.IPv4)
	if !ok || ip.Protocol != layers.IPProtocolTCP {
		return false
	}
	name, ok := extractSNIFromClientHello(tcp.Payload)
	if !ok {
		return false
	}
	src, ok := netip.AddrFromSlice(ip.SrcIP)
	if !ok || c.resolvers[src.Unmap()] {
		return false
	}
	ts := pkt.Metadata().Timestamp
	device := c.resolve(src.Unmap(), ts)
	if device == "" {
		return false
	}
	dst, ok := netip.AddrFromSlice(ip.DstIP)
	if !ok {
		return false
	}
	if collector.PassiveTCP(device, src.Unmap(), dst.Unmap(), port) {
		return false
	}
	name = canonicalDNSName(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	s.add(factKey{transportFact{device, dst.Unmap(), connectivity.ProtoTCP, port}, name}, factValue{wireTime(ts), "sni", ""})
	return true
}

func (c *FactCollection) releaseDNS() {
	c.bindings = nil
	c.unanswered = nil
	c.csv = nil
	c.resolvers = nil
}

// Take transfers facts to output. The scalar minimum supplies ingestion and LSM.
func (c *FactCollection) Take(minPort uint16, control map[uint16]struct{}) []TopologyEntry {
	c.releaseDNS()
	ftp := map[destinationKey]bool{}
	for k := range c.facts {
		if _, ok := control[k.port]; ok && k.proto == connectivity.ProtoTCP {
			ftp[destinationKey{k.device, k.dst}] = true
		}
	}
	out := make([]TopologyEntry, 0, c.Len())
	c.facts.each(func(k factKey, v factValue) {
		if _, ok := control[k.port]; !ok && k.proto == connectivity.ProtoTCP && k.port >= minPort && ftp[destinationKey{k.device, k.dst}] {
			return
		}
		out = append(out, TopologyEntry{IssuerIP: k.device, DestinationIP: k.dst.String(), DNSName: k.name, DNSSource: v.source, CNAMEChain: v.chain, Protocol: string(k.proto), Port: k.port, ObservedAt: v.first.utc()})
	})
	c.facts = nil
	return UniqueFacts(out)
}

// UniqueFacts reconciles rows after enrichment and returns stable key order.
func UniqueFacts(rows []TopologyEntry) []TopologyEntry {
	slices.SortFunc(rows, func(a, b TopologyEntry) int {
		if a.IssuerIP != b.IssuerIP {
			return cmp.Compare(a.IssuerIP, b.IssuerIP)
		}
		if a.DestinationIP != b.DestinationIP {
			return cmp.Compare(a.DestinationIP, b.DestinationIP)
		}
		if a.Protocol != b.Protocol {
			return cmp.Compare(a.Protocol, b.Protocol)
		}
		if a.Port != b.Port {
			return cmp.Compare(a.Port, b.Port)
		}
		if a.DNSName != b.DNSName {
			return cmp.Compare(a.DNSName, b.DNSName)
		}
		if r := cmp.Compare(topologySourceRank(b.DNSSource), topologySourceRank(a.DNSSource)); r != 0 {
			return r
		}
		if a.DNSSource != b.DNSSource {
			return cmp.Compare(a.DNSSource, b.DNSSource)
		}
		if a.ObservedDNSName != b.ObservedDNSName {
			return cmp.Compare(a.ObservedDNSName, b.ObservedDNSName)
		}
		return a.ObservedAt.Compare(b.ObservedAt)
	})
	out := rows[:0]
	for i, row := range rows {
		if i+1 < len(rows) && row.DNSName == "" {
			b := rows[i+1]
			if row.IssuerIP == b.IssuerIP && row.DestinationIP == b.DestinationIP && row.Protocol == b.Protocol && row.Port == b.Port {
				continue
			}
		}
		if len(out) > 0 {
			p := &out[len(out)-1]
			if row.IssuerIP == p.IssuerIP && row.DestinationIP == p.DestinationIP && row.Protocol == p.Protocol && row.Port == p.Port && row.DNSName == p.DNSName {
				if row.ObservedAt.Before(p.ObservedAt) {
					p.ObservedAt = row.ObservedAt
				}
				continue
			}
		}
		out = append(out, row)
	}
	clear(rows[len(out):])
	return out
}

// CompleteFactsWithActiveDNS decorates an existing contact only if the same
// device had queried the selected name by the time of that contact.
func CompleteFactsWithActiveDNS(rows []TopologyEntry, resolutions []DNSNameIPv4Resolution, txs []*DNSTransaction, window time.Duration) []TopologyEntry {
	if len(resolutions) == 0 || len(rows) == 0 {
		return rows
	}
	out := CompleteTopologyWithActiveDNS(rows, resolutions)
	queries := make(map[nameKey][]time.Time)
	for i, row := range out {
		if row.DNSSource == "active+matrix" && rows[i].DNSName == "" {
			queries[nameKey{row.IssuerIP, row.DNSName}] = nil
		}
	}
	for _, tx := range txs {
		k := nameKey{tx.IssuerLabel, tx.DNSName}
		if _, needed := queries[k]; needed {
			queries[k] = append(queries[k], tx.RequestTime)
		}
	}
	for i, row := range out {
		if row.DNSSource != "active+matrix" || rows[i].DNSName != "" {
			continue
		}
		// The DNS pass publishes transactions sorted by capture time.
		ts := queries[nameKey{row.IssuerIP, row.DNSName}]
		j := sort.Search(len(ts), func(j int) bool { return ts[j].After(row.ObservedAt) })
		if j == 0 || (window > 0 && row.ObservedAt.Sub(ts[j-1]) > window) {
			out[i] = rows[i]
		}
	}
	return out
}
