package syntrail

import (
	"bytes"
	"math"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestCapturedRecordLayout(t *testing.T) {
	t.Logf("Record=%d TCP slot=%d UDP map/order key=%d Protocol=%d", unsafe.Sizeof(Record{}), unsafe.Sizeof(compactTCPRecord{}), unsafe.Sizeof(observedRecordKey{}), unsafe.Sizeof(Protocol(0)))
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if unsafe.Sizeof(Record{}) != 48 || unsafe.Sizeof(compactTCPRecord{}) != 40 || unsafe.Sizeof(observedRecordKey{}) != 72 {
			t.Fatal("record, TCP slot, or unchanged netip UDP-key layout changed")
		}
	}
	if unsafe.Sizeof(Protocol(0)) != 1 || ProtocolTCP != 6 || ProtocolUDP != 17 {
		t.Fatal("unexpected IP protocol representation")
	}
}

func TestRecordCaptureTimestampBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ts      time.Time
		ns, ms  int64
		missing bool
		text    string
	}{
		{"missing", time.Time{}, 0, time.Time{}.UnixMilli(), true, "0001-01-01 00:00:00.000"},
		{"epoch", time.Unix(0, 0), 0, 0, false, "1970-01-01 00:00:00.000"},
		{"negative_ns", time.Unix(0, -1), -1, -1, false, "1969-12-31 23:59:59.999"},
		{"positive_ns", time.Unix(0, 1), 1, 0, false, "1970-01-01 00:00:00.000"},
		{"negative_ms", time.Unix(0, -1000000), -1000000, -1, false, "1969-12-31 23:59:59.999"},
		{"before_negative_ms", time.Unix(0, -1000001), -1000001, -2, false, "1969-12-31 23:59:59.998"},
		{"minimum", time.Unix(0, math.MinInt64), math.MinInt64, -9223372036855, false, "1677-09-21 00:12:43.145"},
		{"maximum", time.Unix(0, math.MaxInt64), math.MaxInt64, 9223372036854, false, "2262-04-11 23:47:16.854"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Record{Timestamp: 27, MissingTime: !tc.missing}
			if err := r.SetTimestamp(tc.ts); err != nil {
				t.Fatal(err)
			}
			if r.Timestamp != tc.ns || r.MissingTime != tc.missing || r.CaptureTime().UnixMilli() != tc.ms {
				t.Fatalf("timestamp=%d missing=%t milliseconds=%d", r.Timestamp, r.MissingTime, r.CaptureTime().UnixMilli())
			}
			if !r.CaptureTime().Equal(tc.ts) || r.CaptureTime().Location() != time.UTC {
				t.Fatalf("capture instant changed: %v", r.CaptureTime())
			}
			if got := FormatTimestampUTC(r.CaptureTime()); got != tc.text {
				t.Fatalf("rendered %q, want %q", got, tc.text)
			}
		})
	}
	for _, ts := range []time.Time{minRecordTime.Add(-time.Nanosecond), maxRecordTime.Add(time.Nanosecond)} {
		r := Record{Timestamp: 17}
		before := r
		if err := r.SetTimestamp(ts); err == nil {
			t.Fatalf("accepted out-of-range timestamp %s", ts)
		}
		if r != before {
			t.Fatal("rejected timestamp mutated record")
		}
	}
}

func TestRecordTimestampOrderingAndTrail(t *testing.T) {
	ordered := []Record{{MissingTime: true}, {Timestamp: math.MinInt64}, {Timestamp: -1}, {}, {Timestamp: 1}, {Timestamp: math.MaxInt64}}
	for i, a := range ordered {
		for j, b := range ordered {
			if a.TimeBefore(b) != (i < j) || a.TimeEqual(b) != (i == j) {
				t.Fatalf("unexpected timestamp relation for %d and %d", i, j)
			}
		}
	}
	// All these timestamps format to either the same millisecond or missing
	// time. Destination order must not mask the exact timestamp ordering.
	records := []Record{
		{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{0, 0, 0, 1}, DstPort: 443, Protocol: ProtocolTCP, Timestamp: 1},
		{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{0, 0, 0, 2}, DstPort: 443, Protocol: ProtocolTCP},
		{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{}, DstPort: 443, Protocol: ProtocolTCP, MissingTime: true},
	}
	var out bytes.Buffer
	if err := WriteProtocolTrailCSV(&out, records); err != nil {
		t.Fatal(err)
	}
	const want = "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n" +
		"10.0.0.1,0.0.0.0,443,tcp,0001-01-01 00:00:00.000\n" +
		"10.0.0.1,0.0.0.2,443,tcp,1970-01-01 00:00:00.000\n" +
		"10.0.0.1,0.0.0.1,443,tcp,1970-01-01 00:00:00.000\n"
	if out.String() != want {
		t.Fatalf("trail order/text changed: %q", out.String())
	}
}

func TestAccumulatorUDPMissingTimestampAndTie(t *testing.T) {
	dated := Record{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{192, 0, 2, 1}, DstPort: 514, Protocol: ProtocolUDP, Timestamp: math.MinInt64}
	missing := dated
	missing.Timestamp, missing.MissingTime, missing.SyslogQualified = 0, true, true
	tie := missing
	tie.SyslogQualified = false
	other := dated
	other.DstPort = 123
	acc := NewAccumulator()
	acc.Add([]Record{dated, other})
	acc.Add([]Record{missing, tie})
	got := acc.TakeRecords()
	if len(got) != 2 || got[0] != missing || got[1] != other {
		t.Fatalf("earliest, first-seen position or first-on-tie changed: %+v", got)
	}
}
