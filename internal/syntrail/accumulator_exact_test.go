package syntrail

import (
	"bytes"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"
)

type tcpEncodingCase struct {
	name   string
	record Record
	common bool
}

// The captured domain is IPv4, TCP/UDP and exact capture instants. Protocol
// zero remains a representable compatibility fallback for caller-supplied records.
func tcpEncodingCases() []tcpEncodingCase {
	base := Record{FleetIdentity: "imsi-a", SrcIP: [4]byte{}, DstIP: [4]byte{255, 255, 255, 255},
		DstPort: 65535, Protocol: ProtocolTCP, SyslogQualified: true}
	cases := []tcpEncodingCase{{"epoch", base, true}}
	for _, tc := range []struct {
		name string
		ns   int64
	}{
		{"negative_ns", -1}, {"positive_ns", 1},
		{"minimum", math.MinInt64}, {"above_minimum", math.MinInt64 + 1},
		{"maximum", math.MaxInt64}, {"below_maximum", math.MaxInt64 - 1},
	} {
		r := base
		r.Timestamp = tc.ns
		cases = append(cases, tcpEncodingCase{tc.name, r, true})
	}
	missing := base
	missing.MissingTime = true
	omitted := base
	omitted.Protocol = 0
	empty := base
	empty.FleetIdentity, empty.DstPort, empty.SyslogQualified = "", 0, false
	return append(cases, tcpEncodingCase{"missing_time", missing, true},
		tcpEncodingCase{"omitted_protocol", omitted, false},
		tcpEncodingCase{"empty_identity_and_port", empty, true})
}

func TestAccumulatorExactRecordOrder(t *testing.T) {
	cases := tcpEncodingCases()
	acc := NewAccumulator()
	var ref referenceAccumulator
	udp := cases[0].record
	udp.Protocol = ProtocolUDP
	other := udp
	other.FleetIdentity = "imsi-b"
	earlier := udp
	earlier.Timestamp--
	tie := earlier
	tie.SyslogQualified = !earlier.SyslogQualified
	add := func(batch []Record) {
		ref.add(batch)
		acc.Add(batch)
		clear(batch)
	}
	add([]Record{udp, other})
	for i := 0; i < 2*accumulatorChunkRecords+3; i++ {
		r := cases[i%len(cases)].record
		if i%4 == 0 {
			r.FleetIdentity = "imsi-b"
		}
		add([]Record{r, r})
		if i == accumulatorChunkRecords/2 {
			add([]Record{earlier, tie})
		}
	}
	got, want := acc.TakeRecords(), ref.records()
	// Full value equality includes missing-time state and all retained flags.
	if !slices.Equal(got, want) {
		t.Fatalf("value or position changed across chunks (%d records, want %d)", len(got), len(want))
	}
}

func TestAccumulatorDebugCSVSubmillisecondOrder(t *testing.T) {
	early := Record{SrcIP: netip.MustParseAddr("10.0.0.1").As4(), DstIP: netip.MustParseAddr("203.0.113.9").As4(),
		DstPort: 443, Protocol: ProtocolTCP, Timestamp: time.Date(2026, 11, 15, 2, 41, 39, 795651000, time.UTC).UnixNano()}
	late := early
	late.Timestamp = early.Timestamp + int64(87*time.Microsecond)
	late.DstIP = netip.MustParseAddr("203.0.113.1").As4()
	acc := NewAccumulator()
	acc.Add([]Record{late, early})
	var csv bytes.Buffer
	if err := WriteTCPProtocolTrailCSV(&csv, acc.TakeRecords()); err != nil {
		t.Fatal(err)
	}
	const want = "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n" +
		"10.0.0.1,203.0.113.9,443,tcp,2026-11-15 02:41:39.795\n" +
		"10.0.0.1,203.0.113.1,443,tcp,2026-11-15 02:41:39.795\n"
	if csv.String() != want {
		t.Fatalf("debug CSV order changed: %q", csv.String())
	}
}
