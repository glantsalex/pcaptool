package radius

import (
	"net/netip"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/syntrail"
)

func TestRecord48PacketTimeLookupPreservesMillisecondFloor(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	idx := NewIMSIIndex()
	missingMillis := time.Time{}.UnixMilli()
	idx.byIP[ip] = []SessionWindow{
		{StartMs: missingMillis, EndMs: missingMillis, IMSI: "missing"},
		{StartMs: -2, EndMs: -2, IMSI: "earlier"},
		{StartMs: -1, EndMs: -1, IMSI: "before-epoch"},
		{StartMs: 0, EndMs: 0, IMSI: "epoch"},
	}
	for _, tc := range []struct {
		name   string
		record syntrail.Record
		want   string
	}{
		{"missing", syntrail.Record{MissingTime: true}, "missing"},
		{"minus one nanosecond", syntrail.Record{Timestamp: -1}, "before-epoch"},
		{"minus one millisecond", syntrail.Record{Timestamp: -1_000_000}, "before-epoch"},
		{"before minus one millisecond", syntrail.Record{Timestamp: -1_000_001}, "earlier"},
		{"epoch", syntrail.Record{}, "epoch"},
		{"plus one nanosecond", syntrail.Record{Timestamp: 1}, "epoch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.record.SrcIP = ip.As4()
			// This is the Record-to-RADIUS boundary used by the CLI's packet-time
			// fleet resolver. Dividing nanoseconds toward zero would pick the
			// wrong subscriber at the epoch boundary.
			got, ok := idx.LookupAddr(tc.record.SrcAddr(), tc.record.CaptureTime())
			if got != tc.want || !ok {
				t.Fatalf("lookup = (%q, %v), want %q", got, ok, tc.want)
			}
		})
	}
}
