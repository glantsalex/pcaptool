package dns

import (
	"strings"
	"sync"
)

// Hostnames owns the spelling behind every transaction ID in one extraction.
// ID zero denotes an absent name. Callers apply their source's normalization
// before interning, so DNS and legacy SNI keep their existing output spelling.
type Hostnames struct {
	mu   sync.RWMutex
	byID map[uint64]string
}

// NewHostnames creates the dictionary shared by all workers and report readers.
func NewHostnames() *Hostnames { return &Hostnames{byID: make(map[uint64]string, 10000)} }

func (h *Hostnames) intern(name string) uint64 {
	if name == "" {
		return 0
	}
	// FNV-1a, 64 bit. Hash the string bytes without a []byte conversion.
	id := uint64(14695981039346656037)
	for i := 0; i < len(name); i++ {
		id ^= uint64(name[i])
		id *= 1099511628211
	}
	return h.internAt(id, name)
}

func (h *Hostnames) internAt(hash uint64, name string) uint64 {
	h.mu.RLock()
	id, found := h.probe(hash, name)
	h.mu.RUnlock()
	if found {
		return id
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	id, found = h.probe(id, name)
	if !found {
		h.byID[id] = strings.Clone(name)
	}
	return id
}

// probe runs under the dictionary lock. Entries stay immutable for the run.
func (h *Hostnames) probe(id uint64, name string) (uint64, bool) {
	for ; ; id++ {
		if id == 0 {
			continue
		}
		s, ok := h.byID[id]
		if !ok || s == name {
			return id, ok
		}
	}
}

func (h *Hostnames) name(id uint64) string {
	if id == 0 {
		return ""
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byID[id]
}
