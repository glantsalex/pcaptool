package connectivity

import (
	"reflect"
	"testing"
	"time"
)

func TestCollectorPartitionsIdentityBeforeTimestampCap(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	resolve := func(_ string, ts time.Time) string {
		switch {
		case ts.Before(base.Add(time.Second)):
			return "A"
		case ts.Before(base.Add(2 * time.Second)):
			return "B"
		case ts.Before(base.Add(3 * time.Second)):
			return "C"
		default:
			return ""
		}
	}
	var reference []Edge
	for _, reverse := range []bool{false, true} {
		opt := DefaultOptions()
		opt.IssuerIdentity = resolve
		c := NewCollector(opt)
		key := edgeKey{issuer: "10.1.1.1", dst: "203.0.113.1", proto: ProtoTCP, port: 443}
		for n := 0; n < 800; n++ {
			i := n
			if reverse {
				i = 799 - n
			}
			c.recordEdgeObservation(key, base.Add(time.Duration(i)*5*time.Millisecond))
		}
		edges := c.Edges()
		if len(edges) != 4 {
			t.Fatalf("identity groups=%d, want 4", len(edges))
		}
		seen := map[string]bool{}
		for _, e := range edges {
			seen[e.IssuerIdentity] = true
			if len(e.ObservedTimes) != 128 {
				t.Fatalf("group %s timestamps=%d", e.IssuerIdentity, len(e.ObservedTimes))
			}
			if e.FirstSeen != e.ObservedTimes[0] {
				t.Fatal("first-seen not retained")
			}
		}
		if !reflect.DeepEqual(seen, map[string]bool{"A": true, "B": true, "C": true, "10.1.1.1": true}) {
			t.Fatal(seen)
		}
		if reference == nil {
			reference = edges
		} else if !reflect.DeepEqual(reference, edges) {
			t.Fatal("arrival order changed grouped observations")
		}
	}
}

func BenchmarkCollectorTimedIdentity(b *testing.B) {
	opt := DefaultOptions()
	opt.IssuerIdentity = func(string, time.Time) string { return "123456789012345" }
	c := NewCollector(opt)
	key := edgeKey{issuer: "10.1.1.1", dst: "203.0.113.1", proto: ProtoTCP, port: 443}
	base := time.Unix(0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.recordEdgeObservation(key, base.Add(time.Duration(i)))
	}
}
