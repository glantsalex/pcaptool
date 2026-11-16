package radius

import "sort"

const (
	acctStatusStart   = uint32(1)
	acctStatusStop    = uint32(2)
	acctStatusInterim = uint32(3)
)

// SessionWindow describes inclusive UTC millisecond bounds for an IP assignment.
// An inferred end is limited to the analyzed capture window, never processing time.
type SessionWindow struct {
	IMSI           string
	IP             string
	SessionID      string
	StartMs        int64
	EndMs          int64
	lastEvidenceMs int64
	confirmedStart bool
	inferredEnd    bool
}

type sessionKey struct{ imsi, ip, sid string }

// buildSessionWindows consumes accounting messages in timestamp order. Duration
// can reconstruct a missing Start; absent duration never invents earlier ownership.
func buildSessionWindows(msgs []radMsg, captureEndMs int64) []SessionWindow {
	open := make(map[sessionKey]*SessionWindow)
	stopped := make(map[sessionKey]int64)
	windows := make([]SessionWindow, 0)
	for _, m := range msgs {
		key := sessionKey{m.imsi, m.ip, m.sid}
		start := m.tsMs
		if m.status != radStart && m.hasSessionTime {
			start -= int64(m.sessTimeSec) * 1000
		}
		w := open[key]
		if w == nil {
			// A delayed update for a session already stopped cannot reopen it.
			if stop, ok := stopped[key]; ok && m.status != radStart && start <= stop {
				continue
			}
			w = &SessionWindow{IMSI: m.imsi, IP: m.ip, SessionID: m.sid, StartMs: start, lastEvidenceMs: m.tsMs}
			open[key] = w
		}
		if m.status == radStart {
			if !w.confirmedStart {
				// A delayed Start must not erase earlier accounting evidence
				// already observed for the same assignment.
				w.StartMs = min(w.StartMs, m.tsMs)
			}
			w.confirmedStart = true
		} else if !w.confirmedStart && m.hasSessionTime && start < w.StartMs {
			w.StartMs = start
		}
		w.lastEvidenceMs = m.tsMs
		if m.status == radStop {
			w.EndMs = m.tsMs
			windows = append(windows, *w)
			delete(open, key)
			stopped[key] = m.tsMs
		}
	}
	for _, w := range open {
		w.EndMs = max(captureEndMs, w.lastEvidenceMs)
		w.inferredEnd = true
		windows = append(windows, *w)
	}
	sort.Slice(windows, func(i, j int) bool {
		a, b := windows[i], windows[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.StartMs != b.StartMs {
			return a.StartMs < b.StartMs
		}
		if a.IMSI != b.IMSI {
			return a.IMSI < b.IMSI
		}
		if a.SessionID != b.SessionID {
			return a.SessionID < b.SessionID
		}
		return a.EndMs < b.EndMs
	})
	// Shorten only an inferred tail unsupported by later accounting evidence.
	// Contradictory overlaps remain visible to Lookup, which refuses ambiguity.
	for i := range windows {
		w := &windows[i]
		if !w.inferredEnd {
			continue
		}
		for j := i + 1; j < len(windows) && windows[j].IP == w.IP; j++ {
			next := windows[j]
			if next.StartMs > w.EndMs {
				break
			}
			if next.IMSI != w.IMSI && next.StartMs > w.lastEvidenceMs {
				w.EndMs = next.StartMs - 1
				break
			}
		}
	}
	return windows
}
