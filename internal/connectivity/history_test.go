package connectivity

import (
	"math"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestObservationHistoryAcrossNanoLimits(t *testing.T) {
	minimum, maximum := time.Unix(0, math.MinInt64).UTC(), time.Unix(0, math.MaxInt64).UTC()
	events := []time.Time{time.Time{}, time.Unix(0, 0), time.Unix(0, -1), time.Unix(0, 1), maximum, minimum}
	h := NewObservationHistory(events...)
	if len(h.nanos) != 5 || h.wide != nil {
		t.Fatalf("expected five compact instants: %+v", h)
	}
	// Exercise promotion on both sides and saturation in both input orders.
	for _, outside := range []time.Time{minimum.Add(-1), maximum.Add(1)} {
		input := append(slices.Clone(events), outside, outside.In(time.FixedZone("offset", 3600)))
		for i := 0; i < 160; i++ {
			input = append(input, time.Unix(0, int64(i)))
		}
		for pass := 0; pass < 2; pass++ {
			var history ObservationHistory
			var want []time.Time
			for _, ts := range input {
				history.add(ts)
				want = legacyMergeEdgeObservedTimes(want, ts)
			}
			got := slices.Collect((Edge{ObservedTimes: history}).ObservationTimes())
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("wide history differs: %v vs %v", got, want)
			}
			slices.Reverse(input)
		}
	}
}

func TestOwnedMergeMatchesIndependentUnion(t *testing.T) {
	for _, start := range []time.Time{time.Unix(0, -100), minNanoTime.Add(-1000), maxNanoTime.Add(-50)} {
		var left, right []time.Time
		for i := 0; i < 128; i++ {
			left = append(left, start.Add(time.Duration(i*3)))
			right = append(right, start.Add(time.Duration(i*2-5)))
		}
		dst, src := NewObservationHistory(left...), NewObservationHistory(right...)
		srcBefore := src.Clone()
		want := legacyMergeEdgeObservedTimes(legacyMergeEdgeObservedTimes(nil, left...), right...)
		dst.MergeOwned(src)
		got := slices.Collect((Edge{ObservedTimes: dst}).ObservationTimes())
		if !slices.Equal(got, want) || !reflect.DeepEqual(src, srcBefore) {
			t.Fatalf("incorrect owned merge at %v", start)
		}
	}
}

func TestSaturatedCompactMergeReusesStorage(t *testing.T) {
	var history ObservationHistory
	for i := 0; i < 128; i++ {
		history.add(time.Unix(0, int64(i)))
	}
	before := &history.nanos[0]
	source := NewObservationHistory(time.Unix(0, -1), time.Unix(0, 129))
	history.MergeOwned(source)
	if &history.nanos[0] != before || history.At(0).UnixNano() != -1 || history.At(127).UnixNano() != 129 {
		t.Fatal("expected bounded update in existing storage")
	}
}
