package syntrail

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// referenceAccumulator freezes the pre-chunk public contract, including timed
// identity partitioning missing from the older legacy scan test helper.
type referenceAccumulator struct {
	tcp   []Record
	udp   map[referenceUDPKey]Record
	order []referenceUDPKey
}

type referenceUDPKey struct {
	identity string
	src, dst [4]byte
	port     uint16
	protocol Protocol
}

func (a *referenceAccumulator) add(records []Record) {
	for _, r := range records {
		if r.Protocol != ProtocolUDP {
			a.tcp = append(a.tcp, r)
			continue
		}
		if a.udp == nil {
			a.udp = make(map[referenceUDPKey]Record)
		}
		key := referenceUDPKey{r.FleetIdentity, r.SrcIP, r.DstIP, r.DstPort, r.Protocol}
		old, exists := a.udp[key]
		if !exists {
			a.order = append(a.order, key)
		}
		if !exists || r.TimeBefore(old) {
			a.udp[key] = r
		}
	}
}

func (a *referenceAccumulator) records() []Record {
	var out []Record
	out = append(out, a.tcp...)
	for _, key := range a.order {
		out = append(out, a.udp[key])
	}
	return out
}

func TestAccumulatorContractDifferential(t *testing.T) {
	for _, seed := range []int64{1, 42, 301686} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			acc := NewAccumulator()
			var reference referenceAccumulator
			addresses := []netip.Addr{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("255.255.255.255")}
			protocols := []Protocol{ProtocolTCP, ProtocolUDP, 0}
			identities := []string{"", "device-a", "device-b"}
			base := time.Date(2026, 11, 15, 12, 0, 0, 123456789, time.FixedZone("capture", 2*60*60))
			for file := 0; file < 200; file++ {
				batch := make([]Record, 800)
				for i := range batch {
					batch[i] = Record{
						FleetIdentity: identities[rng.Intn(len(identities))],
						SrcIP:         addresses[rng.Intn(len(addresses))].As4(), DstIP: addresses[rng.Intn(len(addresses))].As4(),
						DstPort: uint16(rng.Intn(8)), Protocol: protocols[rng.Intn(len(protocols))],
						Timestamp:       base.Add(time.Duration(rng.Intn(100)-50) * time.Nanosecond).UnixNano(),
						SyslogQualified: rng.Intn(2) == 0,
					}
					if i%19 == 0 {
						batch[i].Timestamp, batch[i].MissingTime = 0, true
					}
				}
				reference.add(batch)
				acc.Add(batch)
				// Add must copy values, not retain the caller's backing array.
				clear(batch)
				acc.Add(nil)
			}
			if got, want := acc.TakeRecords(), reference.records(); !reflect.DeepEqual(got, want) {
				t.Fatalf("records differ from reference: got %d, want %d", len(got), len(want))
			}
		})
	}
}

func TestAccumulatorContractEmptyAndOrdering(t *testing.T) {
	base := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	tcp := Record{FleetIdentity: "device-a", SrcIP: netip.MustParseAddr("10.0.0.1").As4(), DstIP: netip.MustParseAddr("203.0.113.1").As4(), DstPort: 443, Protocol: ProtocolTCP, Timestamp: base.UnixNano()}
	udp := tcp
	udp.Protocol = ProtocolUDP
	otherIdentity := udp
	otherIdentity.FleetIdentity = "device-b"
	earlier := udp
	earlier.Timestamp = base.Add(-time.Second).UnixNano()
	earlier.SyslogQualified = true
	tie := earlier
	tie.SyslogQualified = false
	for _, tc := range []struct {
		name    string
		batches [][]Record
		want    []Record
	}{
		{"empty", nil, nil},
		{"empty_adds", [][]Record{nil, {}}, nil},
		{"tcp_duplicates", [][]Record{{tcp}, {tcp}}, []Record{tcp, tcp}},
		{"udp_identity_earliest_tie", [][]Record{{udp, otherIdentity}, {earlier, tie}}, []Record{earlier, otherIdentity}},
		{"tcp_before_udp", [][]Record{{udp, tcp}, {otherIdentity, tcp, earlier}}, []Record{tcp, tcp, earlier, otherIdentity}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acc := NewAccumulator()
			for _, batch := range tc.batches {
				acc.Add(batch)
			}
			if got := acc.TakeRecords(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}
