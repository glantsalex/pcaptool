// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package radius

import "sync"

type radStatus uint32

const (
	radStart  radStatus = 1
	radInterm radStatus = 2
	radStop   radStatus = 3
)

type radMsg struct {
	tsMs        int64
	imsi        string
	ip          string
	sid         string
	sessTimeSec uint32
	status      radStatus
}

type radiusCollector struct {
	mu   sync.Mutex
	msgs []radMsg
}

func NewRadiusCollector(capHint int) *radiusCollector {
	if capHint <= 0 {
		capHint = 4096
	}
	return &radiusCollector{msgs: make([]radMsg, 0, capHint)}
}

// Add is safe to call from multiple goroutines; use for occasional adds.
func (c *radiusCollector) Add(m radMsg) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
}

// AddBatch reduces lock contention (workers buffer locally, then bulk-append).
func (c *radiusCollector) AddBatch(batch []radMsg) {
	if len(batch) == 0 {
		return
	}
	c.mu.Lock()
	c.msgs = append(c.msgs, batch...)
	c.mu.Unlock()
}

// Drain hands out the accumulated slice and resets internal storage to nil.
// After Drain, the collector is empty and can be reused or left to GC.
func (c *radiusCollector) Drain() []radMsg {
	c.mu.Lock()
	out := c.msgs
	c.msgs = nil
	c.mu.Unlock()
	return out
}
