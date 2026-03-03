package radius

import (
	"crypto/sha1"
	"sync"
	"time"
)

type deduper struct {
	ttl    time.Duration
	shards []dedupShard
}

type dedupShard struct {
	mu   sync.Mutex
	data map[string]time.Time
	tick int
}

func newDeduper(ttl time.Duration, shards int) *deduper {
	if shards <= 0 {
		shards = 64
	}
	ds := make([]dedupShard, shards)
	for i := range ds {
		ds[i].data = make(map[string]time.Time, 4096)
	}
	return &deduper{ttl: ttl, shards: ds}
}

func (d *deduper) Seen(key string, ts time.Time) bool {
	h := sha1.Sum([]byte(key))
	idx := int(h[0]) % len(d.shards)
	s := &d.shards[idx]
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.data[key]; ok {
		if ts.Sub(t) <= d.ttl {
			return true
		}
	}
	s.data[key] = ts
	s.tick++
	if (s.tick & 0x0FFF) == 0 { // periodic GC
		cut := ts.Add(-d.ttl)
		for k, t := range s.data {
			if t.Before(cut) {
				delete(s.data, k)
			}
		}
	}
	return false
}
