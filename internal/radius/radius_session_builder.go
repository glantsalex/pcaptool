package radius

import (
	"sort"
	"time"
)

// ---- Acct-Status-Type constants
const (
	acctStatusStart   = uint32(1)
	acctStatusStop    = uint32(2)
	acctStatusInterim = uint32(3)
)

// ===== Helpers: time in ms (UTC) =====
func toMs(t time.Time) int64 { return t.UTC().UnixMilli() }

const (
	minuteMs      = int64(time.Minute / time.Millisecond)
	synthGraceMs  = 5 * minuteMs // synthetic Start prior to first Interim/Stop
	lateEpsMs     = 2 * minuteMs // allow tiny late Interim to extend last closed (in-run only)
	coalesceEpsMs = 2 * minuteMs // merge adjacent fragments of same (IMSI,IP,SID)
	hourMs        = int64(time.Hour / time.Millisecond)
	dupStartEpsMs = int64(5 * time.Second / time.Millisecond) // treat near-duplicate Start as no-op
)

// SessionWindow represents a closed or open session for (IMSI, IP, SessionID).
type SessionWindow struct {
	IMSI        string
	IP          string
	SessionID   string
	StartMs     int64
	EndMs       int64
	provisional bool // opened by Interim without a confirming Start (this run)

}

func (w *SessionWindow) Key() string {
	if w.SessionID == "" {
		w.SessionID = "-"
	}
	return w.IMSI + "|" + w.IP + "|" + w.SessionID
}

// sessionBuilder manages in-run session state.
type sessionBuilder struct {
	open       map[string]*SessionWindow // key: imsi|ip|sid
	lastClosed map[string]SessionWindow  // for late Interim within epsilon
	final      []SessionWindow           // closed windows produced in this run
	// fast lookup for “same (IMSI,IP), different SID”:
	openIdx map[string]map[string]*SessionWindow // key: imsi|ip -> sid -> *SessionWindow
	//TODO remove after debugging
	repeatedStart map[string]int // counts of repeated Starts for same key (for stats/debug)

	//TODO remove these and related code after debugging
	addedThisRunByStart   int
	addedThisRunByInterim int
	deletedThisRunByStop  int
	deletedThisRunByStart int

	// minimal run-counters
	closedCount int64
	lastSeenMs  int64 // max ts seen during ingest (ms since epoch)
}

func newSessionBuilder() *sessionBuilder {
	return &sessionBuilder{
		open:          make(map[string]*SessionWindow, 1024),
		openIdx:       make(map[string]map[string]*SessionWindow, 1024),
		lastClosed:    make(map[string]SessionWindow, 1024),
		final:         make([]SessionWindow, 0, 2048),
		repeatedStart: make(map[string]int, 1024),
	}
}

func (b *sessionBuilder) ClosedCount() int { return len(b.final) }

func sessKey(imsi, ip, sid string) string {
	if sid == "" {
		sid = "-"
	}
	return imsi + "|" + ip + "|" + sid
}

func pairKey(imsi, ip string) string { return imsi + "|" + ip }

func (b *sessionBuilder) indexAdd(sw *SessionWindow) {
	p := pairKey(sw.IMSI, sw.IP)
	bySid := b.openIdx[p]
	if bySid == nil {
		bySid = make(map[string]*SessionWindow, 2)
		b.openIdx[p] = bySid
	}
	bySid[sw.SessionID] = sw
}

func (b *sessionBuilder) indexDel(imsi, ip, sid string) {
	p := pairKey(imsi, ip)
	if bySid, ok := b.openIdx[p]; ok {
		delete(bySid, sid)
		if len(bySid) == 0 {
			delete(b.openIdx, p)
		}
	}
}

// closeToFinal closes and archives one open window.
func (b *sessionBuilder) closeToFinal(sw *SessionWindow) {
	b.final = append(b.final, *sw)
	delete(b.open, sw.Key())
	b.indexDel(sw.IMSI, sw.IP, sw.SessionID)
	b.lastClosed[sw.Key()] = *sw
	b.closedCount++
}

// Ingest applies Start/Interim/Stop with late-Interim extension (in-run only; not across runs).
func (b *sessionBuilder) ingest(tsMs int64, status radStatus, imsi, ip, sid string, sessTimeSec uint32) {

	if imsi == "" || ip == "" || status == 0 {
		return
	}

	key := sessKey(imsi, ip, sid)

	if tsMs > b.lastSeenMs {
		b.lastSeenMs = tsMs
	}

	switch status {
	case radStart:
		// 1) Close any other open SIDs for this (IMSI,IP) before handling this Start.
		if bySid, ok := b.openIdx[pairKey(imsi, ip)]; ok {
			for otherSID, other := range bySid {
				if otherSID == sid {
					continue
				}
				// Close previous session just before this Start
				if other.EndMs >= tsMs {
					other.EndMs = tsMs - 1
				}
				b.closeToFinal(other)
				b.deletedThisRunByStart++
			}
		}
		// 2) Idempotent Start inside the current window → no-op (but clear provisional)
		if sw, ok := b.open[key]; ok {
			//TODO remove after debugging
			b.repeatedStart[key]++
			// If this Start falls within, or just touches, the already-open window → NO-OP (idempotent Start).
			// This prevents creation of a zero-length “stub” window after a synthetic Interim-based open.
			if tsMs >= sw.StartMs-dupStartEpsMs && tsMs <= sw.EndMs+dupStartEpsMs {
				sw.provisional = false // confirmed by Start
				return
			}
		}
		// 3) Open a new session for this SID
		nw := &SessionWindow{
			IMSI:        imsi,
			IP:          ip,
			SessionID:   sid,
			StartMs:     tsMs,
			EndMs:       tsMs,
			provisional: false,
		}
		b.open[key] = nw
		b.indexAdd(nw)
		b.addedThisRunByStart++

	case radInterm:
		if sw, ok := b.open[key]; ok {
			if tsMs > sw.EndMs {
				sw.EndMs = tsMs
			}
			return
		}

		if lc, ok := b.lastClosed[key]; ok && tsMs-lc.EndMs <= lateEpsMs {
			lc.EndMs = tsMs
			b.lastClosed[key] = lc
			b.final = append(b.final, lc) // coalesced later
			return
		}
		// Synthetic open from Interim (mark as provisional) — backdate by Acct-Session-Time.
		back := int64(sessTimeSec) * 1000
		nw := &SessionWindow{IMSI: imsi, IP: ip, SessionID: sid, StartMs: tsMs - back, EndMs: tsMs, provisional: true}

		b.open[key] = nw
		b.indexAdd(nw)
		b.addedThisRunByInterim++

	case radStop:

		if sw, ok := b.open[key]; ok {
			sw.EndMs = tsMs
			b.closeToFinal(sw)
			b.deletedThisRunByStop++
			return
		}
		// No open/interim seen (common at beginning of backfill):
		back := max(int64(sessTimeSec)*1000, 0)
		w := SessionWindow{
			IMSI: imsi, IP: ip, SessionID: sid,
			StartMs: tsMs - back,
			EndMs:   tsMs,
		}
		b.final = append(b.final, w)
		b.lastClosed[key] = w
	}
}

// closedCoalesced returns CLOSED windows collected so far (does not close currently open ones).
func (b *sessionBuilder) closedCoalesced() []SessionWindow {

	wins := make([]SessionWindow, len(b.final))
	copy(wins, b.final)

	if len(wins) == 0 {
		return nil
	}

	sort.Slice(wins, func(i, j int) bool {
		if wins[i].IMSI == wins[j].IMSI {
			if wins[i].IP == wins[j].IP {
				if wins[i].SessionID == wins[j].SessionID {
					return wins[i].StartMs < wins[j].StartMs
				}
				return wins[i].SessionID < wins[j].SessionID
			}
			return wins[i].IP < wins[j].IP
		}
		return wins[i].IMSI < wins[j].IMSI
	})

	out := wins[:0]
	for _, w := range wins {
		if len(out) == 0 {
			out = append(out, w)
			continue
		}
		last := &out[len(out)-1]
		same := last.IMSI == w.IMSI && last.IP == w.IP && last.SessionID == w.SessionID
		touches := w.StartMs <= last.EndMs+coalesceEpsMs
		if same && touches {
			if w.EndMs > last.EndMs {
				last.EndMs = w.EndMs
			}
			continue
		}
		out = append(out, w)
	}
	return out
}

// FinalizeForReplay closes:
//   - provisional windows (opened by Interim without a confirming Start), and
//   - any window whose EndMs is older than (tailMs - idleCutoff).
//
// If capAtTail is true, remaining opens get EndMs := min(EndMs, tailMs).
func (b *sessionBuilder) finalizeForReplay(tailMs int64, idleCutoff time.Duration, capAtTail bool) {

	if tailMs == 0 {
		tailMs = b.lastSeenMs
	}

	if tailMs == 0 {
		return
	}

	cutMs := tailMs - int64(idleCutoff/time.Millisecond)

	//TODO remove after debugging
	finalized := 0
	for p, bySid := range b.openIdx {
		for sid, sw := range bySid {
			if sw.provisional || sw.EndMs <= cutMs {
				// prune: treat as closed
				if sw.EndMs > tailMs {
					sw.EndMs = tailMs
				}
				b.final = append(b.final, *sw)
				delete(b.open, sw.Key())
				delete(bySid, sid)
				finalized++
				b.closedCount++
				continue
			}
			if capAtTail && sw.EndMs > tailMs {
				sw.EndMs = tailMs
			}
		}
		if len(bySid) == 0 {
			delete(b.openIdx, p)
		}
	}

}
