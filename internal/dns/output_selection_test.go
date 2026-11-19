package dns

import (
	"encoding/json"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestConnectedOutputRecordsMatchesLegacy(t *testing.T) {
	p443, p0 := uint16(443), uint16(0)
	txs := []*DNSTransaction{
		{IssuerIP: net.ParseIP("10.0.0.1"), DNSName: "same", DestinationPort: &p443, RequestTime: time.Unix(100, 999999)},
		{IssuerIP: net.ParseIP("10.0.0.1"), DNSName: "same", DestinationPort: &p443, RequestTime: time.Unix(0, 0)}, // earlier duplicate must not replace first
		{IssuerLabel: "a|b", DNSName: "c", DestinationPort: &p443},
		{IssuerLabel: "a", DNSName: "b|c", DestinationPort: &p443}, // preserve concatenated-key collision
		{IssuerIP: net.ParseIP("2001:db8::1"), DNSName: "v6", DestinationPort: &p0, RequestTime: time.Unix(-1, 123)},
		{IssuerIP: net.IP{}, DNSName: "empty", DestinationPort: &p443},
		{DNSName: "nil", DestinationPort: &p443},
		{IssuerLabel: "imsi", DNSName: "no connection"},
		{IssuerLabel: "imsi", IssuerIP: net.ParseIP("10.0.0.2"), ResolverIP: net.ParseIP("2001:db8::2"), DNSName: "evidence", DestinationPort: &p443, PCAPFile: "one.cap", NameEvidence: EvDNSAnswer},
	}
	txs[0].AddResolvedIP(net.ParseIP("8.8.8.8"), EvDNSAnswer)
	txs[1].AddResolvedIP(net.ParseIP("1.1.1.1"), EvDNSAnswer)
	txs[len(txs)-1].AddResolvedIP(net.ParseIP("192.0.2.1"), EvDNSAnswer)
	txs[len(txs)-1].AddResolvedIP(net.ParseIP("192.0.2.1"), EvSNI)
	txs[len(txs)-1].AddResolvedIP(net.ParseIP("192.0.2.2"), EvDNSAnswer)
	for seed := int64(0); seed < 20; seed++ {
		input := append([]*DNSTransaction{}, txs...)
		if seed > 0 {
			rand.New(rand.NewSource(seed)).Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		}
		all := ToOutputRecords(input)
		want := FilterAndDedupRecords(all)
		got := ConnectedOutputRecords(input)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: output fields/winner/order differ", seed)
		}
		SortOutputRecords(got)
		SortOutputRecords(want)
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			t.Fatal("JSON bytes differ")
		}
		if !reflect.DeepEqual(ToOutputRecords(input), all) {
			t.Fatal("mutated transactions")
		}
	}
	for _, input := range [][]*DNSTransaction{nil, {}, {{DNSName: "no port"}}} {
		if got, want := ConnectedOutputRecords(input), FilterAndDedupRecords(ToOutputRecords(input)); !reflect.DeepEqual(got, want) {
			t.Fatal("empty contract differs")
		}
	}
}

func BenchmarkConnectedOutputSelection(b *testing.B) {
	p := uint16(443)
	txs := make([]*DNSTransaction, 100000)
	for i := range txs {
		tx := &DNSTransaction{IssuerLabel: "device", DNSName: "name", RequestTime: time.Unix(int64(i), 123), ResolverIP: net.ParseIP("10.0.0.1"), DestinationPort: &p}
		if i%2 == 0 {
			tx.DestinationPort = nil
		}
		tx.AddResolvedIP(net.ParseIP("8.8.8.8"), EvDNSAnswer)
		txs[i] = tx
	}
	for _, early := range []bool{false, true} {
		name := "render_then_filter"
		if early {
			name = "filter_then_render"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var rows []OutputRecord
				if early {
					rows = ConnectedOutputRecords(txs)
				} else {
					rows = FilterAndDedupRecords(ToOutputRecords(txs))
				}
				if len(rows) != 1 {
					b.Fatal("unexpected winners")
				}
			}
		})
	}
}
