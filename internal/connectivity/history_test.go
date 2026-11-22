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
