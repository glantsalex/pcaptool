package dns

import (
	"bytes"
	"math/rand"
	"net"
	"testing"
)

// legacyAnswers is the pre-compaction storage model. Differential checks retain
// its independent slice/map semantics rather than reproducing the compact layout.
type legacyAnswers struct {
	ips      []net.IP
	evidence map[string]Evidence
	name     Evidence
}

func (s *legacyAnswers) add(ip net.IP, ev Evidence) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	key := ip4.String()
	if s.evidence == nil {
		s.evidence = make(map[string]Evidence, 4)
	}
	for _, existing := range s.ips {
		if existing.Equal(ip4) {
			s.evidence[key] |= ev
			return
		}
	}
	s.ips = append(s.ips, append(net.IP(nil), ip4...))
	s.evidence[key] |= ev
}

func (s *legacyAnswers) observe(ip net.IP, allowAdd bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	for _, existing := range s.ips {
		if existing.Equal(ip4) {
			s.evidence[ip4.String()] |= EvObservedConn
			return
		}
	}
	if allowAdd {
		s.add(ip4, EvConnInferred|EvObservedConn|s.name)
	}
}

func TestCompactAnswersMatchLegacyMutationSequence(t *testing.T) {
	for seed := int64(0); seed < 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		tx := &DNSTransaction{NameEvidence: Evidence(rng.Uint32())}
		old := legacyAnswers{name: tx.NameEvidence}
		for step := 0; step < 500; step++ {
			var ip net.IP
			switch rng.Intn(7) {
			case 0:
				ip = nil
			case 1:
				ip = net.IP{}
			case 2:
				ip = net.ParseIP("2001:db8::1")
			case 3:
				ip = append(net.IP(nil), net.IPv4zero...)
			default:
				ip = net.IPv4(192, 0, 2, byte(rng.Intn(64)))
				if rng.Intn(2) == 0 {
					ip = ip.To4()
				}
			}
			// Both receive the same mutable input, then it is destroyed. Neither
			// model may retain caller-owned bytes.
			if rng.Intn(2) == 0 {
				ev := Evidence(rng.Uint32())
				tx.AddResolvedIP(ip, ev)
				old.add(ip, ev)
			} else {
				allow := rng.Intn(2) == 0
				tx.MarkObservedConn(ip, allow)
				old.observe(ip, allow)
			}
			for i := range ip {
				ip[i] = 0
			}
			if tx.ResolvedIPCount() != len(old.ips) || tx.hasResolvedIPEvidence() != (old.evidence != nil) {
				t.Fatalf("seed=%d step=%d count/map presence", seed, step)
			}
			for i, want := range old.ips {
				if !tx.resolvedIPAt(i).Equal(want) {
					t.Fatalf("seed=%d step=%d answer=%d order/value changed", seed, step, i)
				}
				key := want.String()
				got, ok := tx.resolvedIPEvidenceFor(key)
				ev, present := old.evidence[key]
				if got != ev || ok != present {
					t.Fatalf("seed=%d step=%d key=%q evidence=%v/%v want %v/%v", seed, step, key, got, ok, ev, present)
				}
			}
			for _, key := range []string{"", " 192.0.2.1 ", "192.000.2.1", "::ffff:192.0.2.1", "192.0.2.1:53", "192.0.2.255", "2001:db8::1"} {
				got, ok := tx.resolvedIPEvidenceFor(key)
				ev, present := old.evidence[key]
				if got != ev || ok != present {
					t.Fatalf("raw key changed: %q", key)
				}
			}
		}
	}
}

func TestCompactAnswerViewsMatchLegacyAddressOperations(t *testing.T) {
	ips := []net.IP{nil, {}, net.IP{0, 0, 0, 0}, net.ParseIP("0.0.0.0"), net.IP{192, 0, 2, 1}, net.ParseIP("192.0.2.1"), net.IP{255, 255, 255, 255}}
	tx := withTestResolvedAnswers(&DNSTransaction{}, ips, nil)
	for i, want := range ips {
		view := tx.resolvedIPAt(i)
		if view.String() != want.String() || view.isNil() != (want == nil) || view.isEmpty() != (len(want) == 0) || view.To4().isNil() != (want.To4() == nil) {
			t.Fatalf("address operations changed for index %d", i)
		}
		for j, other := range ips {
			if view.Equal(other) != want.Equal(other) || view.compare(tx.resolvedIPAt(j)) != bytes.Compare(want, other) {
				t.Fatalf("comparison changed for %d/%d", i, j)
			}
		}
	}
}

func TestCompactSingleAnswerMutationsAllocateNothing(t *testing.T) {
	tx := &DNSTransaction{}
	ip := net.ParseIP("192.0.2.1")
	if got := testing.AllocsPerRun(1000, func() {
		tx.answers = resolvedAnswers{}
		tx.AddResolvedIP(ip, EvNone)
		tx.AddResolvedIP(ip, EvDNSAnswer)
		tx.MarkObservedConn(ip, false)
	}); got != 0 {
		t.Fatalf("single-answer mutation allocations=%f want 0", got)
	}
}
