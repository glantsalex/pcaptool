package dns

import (
	"bytes"
	"net"
	"net/netip"
)

// Each answer owns its address bytes. The first answer needs no separate heap
// object; additional answers share a compact slice instead of a map and IP slices.
// Presence is separate from both zero evidence and the valid address 0.0.0.0.
type resolvedAnswer struct {
	addr     [4]byte
	evidence Evidence
	kind     answerKind
	flags    uint8
}

type resolvedAnswers struct {
	first resolvedAnswer
	rest  []resolvedAnswer
}

type answerKind uint8

const (
	answerAbsent answerKind = iota
	answerIPv4
	// The remaining kinds preserve imported fixture addresses. Production
	// mutations always admit IPv4 and store its canonical four-byte form.
	answerMappedIPv4
	answerNil
	answerEmpty
)

const (
	answerHasEvidence uint8 = 1 << iota
	// Only the first entry carries this store-level flag, including when empty.
	answersHaveEvidence
)

// resolvedIPView is an immutable address value. Read helpers are for the
// file/coordinator owner or phases after transaction writers have joined; they
// do not lock or snapshot the answer population. Mutations retain their existing
// locks, and ResolvedIPCount remains the concurrent count accessor.
type resolvedIPView struct {
	addr [4]byte
	kind answerKind
}

func (ip resolvedIPView) String() string {
	if ip.kind != answerIPv4 && ip.kind != answerMappedIPv4 {
		return "<nil>"
	}
	return netip.AddrFrom4(ip.addr).String()
}

func (ip resolvedIPView) To4() resolvedIPView {
	if ip.kind != answerIPv4 && ip.kind != answerMappedIPv4 {
		return resolvedIPView{}
	}
	ip.kind = answerIPv4
	return ip
}

func (ip resolvedIPView) isNil() bool   { return ip.kind == answerAbsent || ip.kind == answerNil }
func (ip resolvedIPView) isEmpty() bool { return ip.isNil() || ip.kind == answerEmpty }

// rawBytes preserves the old byte-wise ordering for four-byte and mapped
// addresses. The temporary arrays stay on the stack in comparisons.
func (ip resolvedIPView) rawBytes() (raw [16]byte, n int) {
	switch ip.kind {
	case answerIPv4:
		copy(raw[:4], ip.addr[:])
		return raw, 4
	case answerMappedIPv4:
		raw[10], raw[11] = 0xff, 0xff
		copy(raw[12:], ip.addr[:])
		return raw, 16
	default:
		return raw, 0
	}
}

func (ip resolvedIPView) Equal(other net.IP) bool {
	raw, n := ip.rawBytes()
	return net.IP(raw[:n]).Equal(other)
}

func (ip resolvedIPView) compare(other resolvedIPView) int {
	a, an := ip.rawBytes()
	b, bn := other.rawBytes()
	return bytes.Compare(a[:an], b[:bn])
}

func (tx *DNSTransaction) resolvedIPLen() int {
	if tx.answers.first.kind == answerAbsent {
		return 0
	}
	return 1 + len(tx.answers.rest)
}

func (tx *DNSTransaction) resolvedIPAt(i int) resolvedIPView {
	if i < 0 || i >= tx.resolvedIPLen() {
		panic("resolved answer index out of range")
	}
	a := &tx.answers.first
	if i > 0 {
		a = &tx.answers.rest[i-1]
	}
	return resolvedIPView{addr: a.addr, kind: a.kind}
}

func (tx *DNSTransaction) hasResolvedIPEvidence() bool {
	return tx.answers.first.flags&answersHaveEvidence != 0
}

func (tx *DNSTransaction) findResolvedAnswer(addr [4]byte) *resolvedAnswer {
	a := &tx.answers.first
	if (a.kind == answerIPv4 || a.kind == answerMappedIPv4) && a.addr == addr {
		return a
	}
	for i := range tx.answers.rest {
		a = &tx.answers.rest[i]
		if (a.kind == answerIPv4 || a.kind == answerMappedIPv4) && a.addr == addr {
			return a
		}
	}
	return nil
}

// resolvedIPEvidenceFor returns raw evidence and key presence. In particular,
// a present EvNone is distinct from a missing entry. The mutation boundary uses
// canonical dotted IPv4 keys; ParseAddr rejects whitespace and leading zeroes,
// and Is4 excludes IPv4-mapped IPv6 spellings. No key normalization or fallback
// is applied here: each consumer retains its own NameEvidence policy.
func (tx *DNSTransaction) resolvedIPEvidenceFor(key string) (Evidence, bool) {
	addr, err := netip.ParseAddr(key)
	if err != nil || !addr.Is4() {
		return EvNone, false
	}
	if a := tx.findResolvedAnswer(addr.As4()); a != nil && a.flags&answerHasEvidence != 0 {
		return a.evidence, true
	}
	return EvNone, false
}

func (tx *DNSTransaction) resolvedIPEvidenceValue(key string) Evidence {
	ev, _ := tx.resolvedIPEvidenceFor(key)
	return ev
}

func (tx *DNSTransaction) appendResolvedAnswer(a resolvedAnswer) {
	if tx.answers.first.kind == answerAbsent {
		a.flags |= tx.answers.first.flags & answersHaveEvidence
		tx.answers.first = a
		return
	}
	tx.answers.rest = append(tx.answers.rest, a)
}

func (tx *DNSTransaction) addResolvedIPv4Locked(addr [4]byte, ev Evidence) {
	if a := tx.findResolvedAnswer(addr); a != nil {
		a.evidence |= ev
		a.flags |= answerHasEvidence
	} else {
		tx.appendResolvedAnswer(resolvedAnswer{addr: addr, evidence: ev, kind: answerIPv4, flags: answerHasEvidence})
	}
	tx.answers.first.flags |= answersHaveEvidence
}

func (tx *DNSTransaction) addResolvedIPView(ip resolvedIPView, ev Evidence) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if ip.kind == answerIPv4 || ip.kind == answerMappedIPv4 {
		tx.addResolvedIPv4Locked(ip.addr, ev)
	}
}

// AddResolvedIP adds an owned copy of ip if missing and ORs evidence flags.
func (tx *DNSTransaction) AddResolvedIP(ip net.IP, ev Evidence) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if ip4 := ip.To4(); ip4 != nil {
		tx.addResolvedIPv4Locked([4]byte(ip4), ev)
	}
}

// MarkObservedConn ORs EvObservedConn for ip if present; if ip missing and allowAdd is true, it will add it.
func (tx *DNSTransaction) MarkObservedConn(ip net.IP, allowAdd bool) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	addr := [4]byte(ip4)
	if a := tx.findResolvedAnswer(addr); a != nil {
		a.evidence |= EvObservedConn
		a.flags |= answerHasEvidence
		tx.answers.first.flags |= answersHaveEvidence
		return
	}
	if allowAdd {
		tx.addResolvedIPv4Locked(addr, EvConnInferred|EvObservedConn|tx.NameEvidence)
	}
}

func (tx *DNSTransaction) ResolvedIPCount() int {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return tx.resolvedIPLen()
}
