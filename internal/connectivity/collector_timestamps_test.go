package connectivity

import (
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"
)

// legacyMergeEdgeObservedTimes freezes the timestamp-selection behavior that
// existed before the collector hot path was optimized. Keep this test helper
// deliberately straightforward: it is the compatibility oracle for artifact
// timestamp quality and ordering.
func legacyMergeEdgeObservedTimes(existing []time.Time, additions ...time.Time) []time.Time {
	times := append([]time.Time(nil), existing...)
	for _, ts := range additions {
		if ts.IsZero() {
			continue
		}
		utc := ts.UTC()
		duplicate := false
		for _, existingTS := range times {
			if existingTS.Equal(utc) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		times = append(times, utc)
	}
	if len(times) == 0 {
		return nil
	}
	sort.Slice(times, func(i, j int) bool {
		return times[i].Before(times[j])
	})
	if len(times) <= maxEdgeObservedTimes {
		return times
	}

	out := make([]time.Time, 0, maxEdgeObservedTimes)
	out = append(out, times[0])
	out = append(out, times[len(times)-(maxEdgeObservedTimes-1):]...)
	return out
}

func TestCollectorRecordEdgeObservationMatchesLegacyAtEveryStep(t *testing.T) {
	base := time.Unix(1700000000, 123456789).UTC()
	locations := []*time.Location{
		time.UTC,
		time.FixedZone("UTC-07", -7*60*60),
		time.FixedZone("UTC+05:30", 5*60*60+30*60),
	}

	for _, seed := range []int64{1, 301686, 404163, 909090} {
		t.Run("seed_"+strconv.FormatInt(seed, 10), func(t *testing.T) {
			observations := []time.Time{
				{},
				base,
				base.In(locations[1]),
				base.Add(-time.Hour).In(locations[2]),
				base.Add(48 * time.Hour),
			}
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 4*maxEdgeObservedTimes; i++ {
				if i%19 == 0 {
					observations = append(observations, time.Time{})
					continue
				}
				if i%13 == 0 {
					observations = append(observations, observations[rng.Intn(len(observations))])
					continue
				}
				offset := time.Duration(rng.Intn(8*maxEdgeObservedTimes)-4*maxEdgeObservedTimes) * time.Second
				observations = append(observations, base.Add(offset).In(locations[rng.Intn(len(locations))]))
			}

			c := NewCollector(DefaultOptions())
			key := edgeKey{issuer: "10.0.0.1", dst: "198.51.100.10", proto: ProtoTCP, port: 443}
			var want []time.Time
			for step, ts := range observations {
				want = legacyMergeEdgeObservedTimes(want, ts)
				c.recordEdgeObservation(key, ts)
				got := c.edges[key]
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("step %d timestamp %s: collector differs from legacy\n got: %#v\nwant: %#v", step, ts, got, want)
				}
				assertCanonicalObservedTimes(t, got)
			}
		})
	}
}

func TestAppendEdgeObservedTimeSaturatedBoundaries(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	full := make([]time.Time, maxEdgeObservedTimes)
	for i := range full {
		full[i] = base.Add(time.Duration(i) * time.Second)
	}

	tests := []struct {
		name     string
		existing []time.Time
		addition time.Time
	}{
		{name: "zero", existing: full, addition: time.Time{}},
		{name: "duplicate", existing: full, addition: full[64].In(time.FixedZone("other", 3600))},
		{name: "new earliest", existing: full, addition: base.Add(-time.Second)},
		{name: "insert at one is discarded", existing: full, addition: base.Add(500 * time.Millisecond)},
		{name: "interior insertion", existing: full, addition: base.Add(63500 * time.Millisecond)},
		{name: "new latest", existing: full, addition: base.Add(500 * time.Second)},
		{
			name:     "insert below capacity",
			existing: []time.Time{base, base.Add(2 * time.Second)},
			addition: base.Add(time.Second),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := append([]time.Time(nil), tt.existing...)
			want := legacyMergeEdgeObservedTimes(existing, tt.addition)
			got := appendEdgeObservedTime(existing, tt.addition)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("owned merge differs from legacy\n got: %#v\nwant: %#v", got, want)
			}
			assertCanonicalObservedTimes(t, got)
		})
	}
}

func TestCollectorExportedEdgesDoNotAliasOwnedTimestamps(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	key := edgeKey{issuer: "10.0.0.1", dst: "198.51.100.10", proto: ProtoTCP, port: 443}
	c := NewCollector(DefaultOptions())
	for i := 0; i < maxEdgeObservedTimes; i++ {
		c.recordEdgeObservation(key, base.Add(time.Duration(i)*time.Second))
	}

	edgesSnapshot := c.Edges()
	firstSeenSnapshot := c.EdgesByFirstSeen()
	if len(edgesSnapshot) != 1 || len(firstSeenSnapshot) != 1 {
		t.Fatalf("expected one edge in both snapshots, got %d and %d", len(edgesSnapshot), len(firstSeenSnapshot))
	}
	edgesBefore := append([]time.Time(nil), edgesSnapshot[0].ObservedTimes...)
	firstSeenBefore := append([]time.Time(nil), firstSeenSnapshot[0].ObservedTimes...)

	mutationSnapshot := c.EdgesByFirstSeen()
	mutationSnapshot[0].ObservedTimes[0] = base.Add(-24 * time.Hour)
	if !c.edges[key][0].Equal(base) {
		t.Fatalf("mutating exported snapshot changed collector-owned first timestamp to %s", c.edges[key][0])
	}

	c.recordEdgeObservation(key, base.Add(-time.Second))
	c.recordEdgeObservation(key, base.Add(63500*time.Millisecond))
	c.recordEdgeObservation(key, base.Add(500*time.Second))
	if !reflect.DeepEqual(edgesSnapshot[0].ObservedTimes, edgesBefore) {
		t.Fatalf("collector updates mutated Edges snapshot\n got: %#v\nwant: %#v", edgesSnapshot[0].ObservedTimes, edgesBefore)
	}
	if !reflect.DeepEqual(firstSeenSnapshot[0].ObservedTimes, firstSeenBefore) {
		t.Fatalf("collector updates mutated EdgesByFirstSeen snapshot\n got: %#v\nwant: %#v", firstSeenSnapshot[0].ObservedTimes, firstSeenBefore)
	}
	if c.edges[key][0].Equal(edgesBefore[0]) {
		t.Fatalf("collector did not retain the new earliest timestamp")
	}
	if !c.edges[key][len(c.edges[key])-1].Equal(base.Add(500 * time.Second)) {
		t.Fatalf("collector did not retain the new latest timestamp")
	}
}

func TestMergeEdgeObservedTimesMatchesLegacyBoundaryCases(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	full := make([]time.Time, maxEdgeObservedTimes)
	for i := range full {
		full[i] = base.Add(time.Duration(i) * time.Second)
	}

	tests := []struct {
		name      string
		existing  []time.Time
		additions []time.Time
	}{
		{name: "nil"},
		{name: "zero additions", additions: []time.Time{{}, {}}},
		{name: "duplicates by instant across locations", additions: []time.Time{base, base.In(time.FixedZone("other", 3600))}},
		{name: "out of order", additions: []time.Time{base.Add(2 * time.Second), base, base.Add(time.Second)}},
		{name: "new earliest at capacity", existing: full, additions: []time.Time{base.Add(-time.Second)}},
		{name: "discard old non-earliest at capacity", existing: full, additions: []time.Time{base.Add(500 * time.Millisecond)}},
		{name: "new latest at capacity", existing: full, additions: []time.Time{base.Add(500 * time.Second)}},
		{name: "bulk overflow", additions: append(append([]time.Time(nil), full...), base.Add(-time.Hour), base.Add(500*time.Second))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeEdgeObservedTimes(tt.existing, tt.additions...)
			want := legacyMergeEdgeObservedTimes(tt.existing, tt.additions...)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("merge differs from legacy\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestMergeEdgeObservedTimesDoesNotAliasInputs(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	backing := make([]time.Time, 8)
	backing[0] = base
	backing[1] = base.Add(time.Second)
	existing := backing[:2]
	beforeBacking := append([]time.Time(nil), backing...)
	additions := []time.Time{base.Add(2 * time.Second)}
	beforeAdditions := append([]time.Time(nil), additions...)

	got := MergeEdgeObservedTimes(existing, additions...)
	if !reflect.DeepEqual(backing, beforeBacking) {
		t.Fatalf("existing backing array was mutated: got %#v want %#v", backing, beforeBacking)
	}
	if !reflect.DeepEqual(additions, beforeAdditions) {
		t.Fatalf("additions were mutated: got %#v want %#v", additions, beforeAdditions)
	}

	got[0] = base.Add(-time.Hour)
	if !reflect.DeepEqual(backing, beforeBacking) {
		t.Fatalf("returned slice aliases existing input: got %#v want %#v", backing, beforeBacking)
	}
}

func assertCanonicalObservedTimes(t *testing.T, times []time.Time) {
	t.Helper()
	if len(times) > maxEdgeObservedTimes {
		t.Fatalf("got %d timestamps, maximum is %d", len(times), maxEdgeObservedTimes)
	}
	for i, ts := range times {
		if ts.IsZero() {
			t.Fatalf("timestamp %d is zero", i)
		}
		if ts.Location() != time.UTC {
			t.Fatalf("timestamp %d is not UTC: %#v", i, ts)
		}
		if i > 0 && !times[i-1].Before(ts) {
			t.Fatalf("timestamps are not strictly increasing at %d: %s then %s", i, times[i-1], ts)
		}
	}
}

func BenchmarkCollectorRecordEdgeObservationSaturated(b *testing.B) {
	base := time.Unix(1700000000, 0).UTC()
	key := edgeKey{issuer: "10.0.0.1", dst: "198.51.100.10", proto: ProtoTCP, port: 443}

	benchmarks := []struct {
		name string
		next func(int) time.Time
	}{
		{name: "duplicate", next: func(int) time.Time { return base }},
		{name: "new_monotonic", next: func(i int) time.Time { return base.Add(time.Duration(maxEdgeObservedTimes+i) * time.Second) }},
		{name: "new_out_of_order", next: func(i int) time.Time {
			return base.Add(-time.Duration(i+1) * time.Nanosecond)
		}},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			c := NewCollector(DefaultOptions())
			for i := 0; i < maxEdgeObservedTimes; i++ {
				c.recordEdgeObservation(key, base.Add(time.Duration(i)*time.Second))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.recordEdgeObservation(key, bm.next(i))
			}
		})
	}
}
