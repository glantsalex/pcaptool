package syntrail

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestSubnetMembership(t *testing.T) {
	fleet, err := ParseFleetSubnets([]string{"10.52.192.17/18", "10.52.192.0/18", "10.81.160.0/19"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		ip   string
		want bool
	}{{"10.52.191.255", false}, {"10.52.192.0", true}, {"10.52.255.255", true}, {"10.53.0.0", false}, {"10.81.160.0", true}, {"10.81.191.255", true}, {"10.81.192.0", false}, {"::ffff:10.52.192.1", false}, {"::1", false}} {
		if got := fleet.Contains(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Fatalf("%s: %v", tt.ip, got)
		}
	}
	for _, values := range [][]string{nil, {}, {""}, {"bad"}, {"10.0.0.1/33"}, {"::/0"}, {"::ffff:10.0.0.1/128"}} {
		if _, err := ParseFleetSubnets(values); err == nil {
			t.Fatalf("accepted %v", values)
		}
	}
	for _, prefix := range []string{"0.0.0.0/0", "10.0.0.0/31", "10.0.0.1/32"} {
		f, err := ParseFleetSubnets([]string{prefix})
		if err != nil || !f.Contains(netip.MustParseAddr("10.0.0.1")) {
			t.Fatalf("%s: %v", prefix, err)
		}
	}
}

func TestHostPrefixesMatchExactFleetClassification(t *testing.T) {
	exact := testFleetSet("10.0.0.1", "10.0.0.2")
	prefixes, err := ParseFleetSubnets([]string{"10.0.0.1/32", "10.0.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{{SrcIP: netip.MustParseAddr("10.0.0.1").As4(), DstIP: netip.MustParseAddr("10.1.0.1").As4(), DstPort: 443}, {SrcIP: netip.MustParseAddr("10.1.0.1").As4(), DstIP: netip.MustParseAddr("10.0.0.2").As4(), DstPort: 22}, {SrcIP: netip.MustParseAddr("10.0.0.1").As4(), DstIP: netip.MustParseAddr("10.0.0.2").As4(), DstPort: 80}}
	if !reflect.DeepEqual(ClassifyRecords(records, exact), ClassifyRecords(records, prefixes)) {
		t.Fatal("host prefix differs from fleet")
	}
}

func TestIMSIDeviceCountsAndUnresolvedCoverage(t *testing.T) {
	records := []Record{endpointRecord("10.0.0.1", "10.1.0.1", 514, ProtocolUDP), endpointRecord("10.0.0.1", "10.1.0.1", 514, ProtocolUDP), endpointRecord("10.0.0.2", "10.1.0.1", 514, ProtocolUDP), endpointRecord("10.0.0.3", "10.1.0.1", 514, ProtocolUDP)}
	records[0].FleetIdentity = "123456789012345"
	records[1].FleetIdentity = "223456789012345"
	records[2].FleetIdentity = records[0].FleetIdentity
	for i := range records {
		records[i].SyslogQualified = true
	}
	accumulator := NewAccumulator()
	accumulator.Add(records[:2])
	accumulator.Add(records[2:])
	retained := accumulator.TakeRecords()
	if len(retained) != 4 {
		t.Fatalf("identity lost before count: %d", len(retained))
	}
	var buf bytes.Buffer
	if err := WritePrivateNonFleetEndpointsJSONWithIMSI(&buf, retained, nil, time.Time{}, true); err != nil {
		t.Fatal(err)
	}
	var doc PrivateNonFleetEndpointsDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := doc.Endpoints[0].Server.Listeners[0]
	if doc.FleetIdentityBasis != "imsi" || got.FleetDevicesCount != 2 || got.UnresolvedFleetIPsCount != 1 {
		t.Fatalf("%s", buf.String())
	}
	records = records[3:]
	doc = buildPrivateNonFleetEndpointsDocumentWithIMSI(records, nil, true)
	if len(doc.Endpoints) != 1 || doc.Endpoints[0].Server.Listeners[0].FleetDevicesCount != 0 {
		t.Fatal("unresolved evidence lost or counted as a device")
	}
}

func BenchmarkFleetSubnetMembership(b *testing.B) {
	fleet, _ := ParseFleetSubnets([]string{"10.181.0.0/16", "10.52.192.0/18", "10.81.160.0/19"})
	inputs := []netip.Addr{netip.MustParseAddr("10.181.1.10"), netip.MustParseAddr("10.81.161.1"), netip.MustParseAddr("192.0.2.1")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fleet.Contains(inputs[i%len(inputs)])
	}
}
