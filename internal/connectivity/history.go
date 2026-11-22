package connectivity

import (
	"iter"
	"math"
	"slices"
	"time"
)

// ObservationHistory retains the earliest and latest 127 distinct UTC instants.
// Ordinary captures use signed Unix nanoseconds. A history that encounters a
// date outside that range uses full timestamps to preserve the instant.
type ObservationHistory struct {
	nanos []int64
	wide  []time.Time
}

var (
	minNanoTime = time.Unix(0, math.MinInt64).UTC()
	maxNanoTime = time.Unix(0, math.MaxInt64).UTC()
)

// NewObservationHistory constructs an ordered history from observations.
func NewObservationHistory(times ...time.Time) ObservationHistory {
	var h ObservationHistory
	for _, ts := range times {
		h.add(ts)
	}
	return h
}

// Len returns the number of retained observations.
func (h ObservationHistory) Len() int { return len(h.nanos) + len(h.wide) }

// At returns the UTC instant at index i, in chronological order.
func (h ObservationHistory) At(i int) time.Time {
	if h.wide != nil {
		return h.wide[i]
	}
	return time.Unix(0, h.nanos[i]).UTC()
}

// Clone gives an independent owner a copy of the timestamp storage.
func (h ObservationHistory) Clone() ObservationHistory {
	return ObservationHistory{nanos: slices.Clone(h.nanos), wide: slices.Clone(h.wide)}
}

func (h *ObservationHistory) add(ts time.Time) {
	if ts.IsZero() {
		return
	}
	if h.wide == nil {
		if !ts.Before(minNanoTime) && !ts.After(maxNanoTime) {
			h.addNano(ts.UnixNano())
			return
		}
		h.wide = make([]time.Time, len(h.nanos))
		for i, n := range h.nanos {
			h.wide[i] = time.Unix(0, n).UTC()
		}
		h.nanos = nil
	}
	h.wide = appendEdgeObservedTime(h.wide, ts)
}

func (h *ObservationHistory) addNano(n int64) {
	at, found := slices.BinarySearch(h.nanos, n)
	if !found {
		h.nanos = insertDistinctTime(h.nanos, at, n)
	}
}

// MergeOwned adds a disjoint input history to a receiver whose backing storage
// the caller exclusively owns. At saturation, compact histories update in place.
func (h *ObservationHistory) MergeOwned(other ObservationHistory) {
	if h.wide == nil && other.wide == nil {
		for _, n := range other.nanos {
			h.addNano(n)
		}
		return
	}
	for i := 0; i < other.Len(); i++ {
		h.add(other.At(i))
	}
}

// ObservationTimes yields the edge's retained instants in order. Older callers
// may supply just FirstSeen without a history.
func (e Edge) ObservationTimes() iter.Seq[time.Time] {
	return func(yield func(time.Time) bool) {
		if e.ObservedTimes.Len() == 0 {
			if !e.FirstSeen.IsZero() {
				yield(e.FirstSeen.UTC())
			}
			return
		}
		for i := 0; i < e.ObservedTimes.Len(); i++ {
			if !yield(e.ObservedTimes.At(i)) {
				return
			}
		}
	}
}
