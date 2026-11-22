package dns

import (
	"net"
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

// withTestResolvedAnswers imports legacy fixture addresses without imposing a
// consumer's evidence fallback. Evidence-only fixture initialization belongs at
// the existing AddResolvedIP call, as it does in production.
func withTestResolvedAnswers(tx *DNSTransaction, ips []net.IP, evidence map[string]Evidence) *DNSTransaction {
	tx.answers = resolvedAnswers{}
	covered := make(map[string]bool)
	for _, ip := range ips {
		a := resolvedAnswer{}
		switch {
		case ip == nil:
			a.kind = answerNil
		case len(ip) == 0:
			a.kind = answerEmpty
		case ip.To4() != nil:
			a.addr = [4]byte(ip.To4())
			a.kind = answerIPv4
			if len(ip) == net.IPv6len {
				a.kind = answerMappedIPv4
			}
		default:
			panic("unsupported non-IPv4 answer fixture")
		}
		if ev, ok := evidence[ip.String()]; ok {
			a.evidence = ev
			a.flags |= answerHasEvidence
			covered[ip.String()] = true
		}
		tx.appendResolvedAnswer(a)
	}
	for key := range evidence {
		if !covered[key] {
			panic("evidence fixture has no matching answer: " + key)
		}
	}
	if evidence != nil {
		tx.answers.first.flags |= answersHaveEvidence
	}
	return tx
}
func testResolvedIPs(tx *DNSTransaction) []net.IP {
	var out []net.IP
	for i := 0; i < tx.resolvedIPLen(); i++ {
		ip := tx.resolvedIPAt(i)
		if ip.isNil() {
			out = append(out, nil)
			continue
		}
		raw, n := ip.rawBytes()
		copyIP := make(net.IP, n)
		copy(copyIP, raw[:n])
		out = append(out, copyIP)
	}
	return out
}
func testResolvedEvidence(tx *DNSTransaction) map[string]Evidence {
	out := make(map[string]Evidence)
	for i := 0; i < tx.resolvedIPLen(); i++ {
		key := tx.resolvedIPAt(i).String()
		if ev, ok := tx.resolvedIPEvidenceFor(key); ok {
			out[key] = ev
		}
	}
	return out
}

func TestAnswerStorageMutationContract(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(map[bool]string{false: "four-byte", true: "mapped"}[mapped], func(t *testing.T) {
			tx := &DNSTransaction{NameEvidence: EvDNSAnswer}
			a := net.ParseIP("192.0.2.1")
			if !mapped {
				a = a.To4()
			}
			tx.AddResolvedIP(nil, EvDNSAnswer)
			tx.AddResolvedIP(net.ParseIP("2001:db8::1"), EvDNSAnswer)
			if tx.ResolvedIPCount() != 0 {
				t.Fatal("invalid answers admitted")
			}
			tx.AddResolvedIP(a, EvDNSAnswer)
			tx.AddResolvedIP(net.ParseIP("192.0.2.2"), EvNone)
			tx.AddResolvedIP(net.ParseIP("192.0.2.1"), EvSNI)
			for i := range a {
				a[i] = 0
			}
			if got := tx.resolvedIPAt(0).String(); got != "192.0.2.1" {
				t.Fatalf("aliased input: %s", got)
			}
			if tx.ResolvedIPCount() != 2 || tx.resolvedIPAt(1).String() != "192.0.2.2" {
				t.Fatal("order or dedup changed")
			}
			if ev, ok := tx.resolvedIPEvidenceFor("192.0.2.1"); !ok || ev != EvDNSAnswer|EvSNI {
				t.Fatalf("OR=%v %v", ev, ok)
			}
			if ev, ok := tx.resolvedIPEvidenceFor("192.0.2.2"); !ok || ev != EvNone {
				t.Fatal("zero evidence lost")
			}
			tx.MarkObservedConn(net.ParseIP("192.0.2.2"), false)
			tx.MarkObservedConn(net.ParseIP("192.0.2.3"), false)
			if tx.ResolvedIPCount() != 2 {
				t.Fatal("allowAdd=false added answer")
			}
			tx.MarkObservedConn(net.ParseIP("192.0.2.3"), true)
			if got := tx.resolvedIPEvidenceValue("192.0.2.3"); got != EvConnInferred|EvObservedConn|EvDNSAnswer {
				t.Fatalf("inferred=%v", got)
			}
			if got := tx.resolvedIPEvidenceValue("192.0.2.2"); got != EvObservedConn {
				t.Fatalf("observed=%v", got)
			}
			tx.AddResolvedIP(net.IPv4zero, EvNone)
			if tx.resolvedIPAt(3).String() != "0.0.0.0" {
				t.Fatal("zero IP must be valid")
			}
		})
	}
}

func TestAnswerEvidencePresenceAndReadContract(t *testing.T) {
	tx := withTestResolvedAnswers(&DNSTransaction{NameEvidence: EvDNSAnswer}, []net.IP{nil, {}, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, map[string]Evidence{"192.0.2.1": EvNone})
	if ev, ok := tx.resolvedIPEvidenceFor("192.0.2.1"); ev != EvNone || !ok {
		t.Fatal("explicit zero")
	}
	if ev, ok := tx.resolvedIPEvidenceFor("192.0.2.2"); ev != EvNone || ok {
		t.Fatal("missing evidence")
	}
	if _, ok := tx.resolvedIPEvidenceFor(" 192.0.2.1 "); ok {
		t.Fatal("raw lookup normalized key")
	}
	if !tx.resolvedIPAt(0).isNil() || tx.resolvedIPAt(1).isNil() || !tx.resolvedIPAt(1).isEmpty() {
		t.Fatal("nil/empty distinction changed")
	}
	if got := tx.resolvedIPAt(2).To4().String(); got != "192.0.2.1" {
		t.Fatal(got)
	}
	if n := testing.AllocsPerRun(1000, func() {
		for i := 0; i < tx.resolvedIPLen(); i++ {
			v := tx.resolvedIPAt(i)
			_ = v.isNil()
			_ = v.To4()
			_ = v.compare(v)
		}
		_, _ = tx.resolvedIPEvidenceFor("192.0.2.1")
	}); n != 0 {
		t.Fatalf("read access allocated: %f", n)
	}
}

func TestAnswerMergePreservesOrderAndFallback(t *testing.T) {
	dst := &DNSTransaction{}
	dst.AddResolvedIP(net.ParseIP("192.0.2.2"), EvObservedConn)
	src := withTestResolvedAnswers(&DNSTransaction{NameEvidence: EvSNI}, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, map[string]Evidence{"192.0.2.1": EvNone, "192.0.2.2": EvDNSAnswer})
	mergeDNSTransaction(dst, src)
	var got []string
	for i := 0; i < dst.resolvedIPLen(); i++ {
		got = append(got, dst.resolvedIPAt(i).String())
	}
	if !reflect.DeepEqual(got, []string{"192.0.2.2", "192.0.2.1"}) {
		t.Fatal(got)
	}
	if dst.resolvedIPEvidenceValue("192.0.2.1") != EvSNI || dst.resolvedIPEvidenceValue("192.0.2.2") != EvDNSAnswer|EvObservedConn {
		t.Fatal("merge fallback changed")
	}
}

// These consumers intentionally have different fallback policies. Storage must
// preserve raw evidence and presence instead of choosing one policy for them.
func TestAnswerConsumerEvidenceFallbacks(t *testing.T) {
	hostnames := NewHostnames()

	const ip = "34.120.10.1"
	const name = "api.example.com"
	nameEvidence := EvDNSAnswer | EvObservedConn
	for _, tt := range []struct {
		name     string
		evidence map[string]Evidence
		output   Evidence
		audit    Evidence
		index    Evidence
		learn    bool
	}{
		{"nil-map", nil, nameEvidence, nameEvidence, nameEvidence, true},
		{"missing", map[string]Evidence{}, nameEvidence, nameEvidence, nameEvidence, true},
		{"explicit-zero", map[string]Evidence{ip: EvNone}, nameEvidence, EvNone, nameEvidence, true},
		{"sni", map[string]Evidence{ip: EvSNI}, EvSNI, EvNone, nameEvidence | EvSNI, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := withTestResolvedAnswers(&DNSTransaction{DNSNameID: hostnames.intern(name), NameEvidence: nameEvidence}, []net.IP{net.ParseIP(ip)}, tt.evidence)
			txs := []*DNSTransaction{tx}
			if got := ToOutputRecords(hostnames, txs)[0].ResolvedIPSources[ip]; got != EvidenceString(tt.output) {
				t.Fatalf("output=%q want %q", got, EvidenceString(tt.output))
			}
			if got := BuildIPDNSAppendAuditRecords(hostnames, txs, []IPDNSPair{{DNS: name, IP: ip}})[0].Evidence; got != EvidenceString(tt.audit) {
				t.Fatalf("audit=%q want %q", got, EvidenceString(tt.audit))
			}
			if got := BuildNameIPEvidenceIndex(hostnames, txs)[nameIPKey(name, ip)]; got != tt.index {
				t.Fatalf("index=%v want %v", got, tt.index)
			}
			if got := len(StrongObservedIPDNSPairsFromTransactions(hostnames, txs)[ip]) > 0; got != tt.learn {
				t.Fatalf("learn=%v want %v", got, tt.learn)
			}
		})
	}
}

func TestAnswerCompactTransactionLayout(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("saved layout baseline is amd64")
	}
	if got := unsafe.Sizeof(DNSTransaction{}); got != 224 {
		t.Fatalf("transaction size=%d want 224", got)
	}
	if got := unsafe.Sizeof(resolvedAnswer{}); got != 8 {
		t.Fatalf("answer size=%d want 8", got)
	}
	if got := unsafe.Sizeof(resolvedAnswers{}); got != 32 {
		t.Fatalf("store size=%d want 32", got)
	}
}
