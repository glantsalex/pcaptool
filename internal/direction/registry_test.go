package direction

import (
	"encoding/json"
	"testing"
)

func TestMergeDatesRolesAndQualification(t *testing.T) {
	old := Document{SchemaVersion: 1, AccountID: "a", StreamID: "s", Endpoints: []Endpoint{}}
	d, err := Decode([]byte(`{"schema_version":1,"endpoints":[{"ip":"10.4.100.58","server":{"listeners":[{"protocol":"tcp","port":1883,"fleet_devices_count":20},{"protocol":"udp","port":6514,"evidence":"syslog"},{"protocol":"udp","port":9000}]},"probe":{"targets":[{"protocol":"tcp","port":22}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Merge(old, d, "a", "s", "2026-10-10")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Endpoints) != 1 || len(first.Endpoints[0].Server.Listeners) != 2 || len(first.Endpoints[0].Probe.Targets) != 1 {
		t.Fatalf("%+v", first)
	}
	second, err := Merge(first, d, "a", "s", "2026-09-10")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range second.Endpoints[0].Server.Listeners {
		if b.FirstSeen != "2026-09-10" || b.LastSeen != "2026-10-10" {
			t.Fatalf("%+v", b)
		}
	}
	third, err := Merge(second, d, "a", "s", "2026-09-10")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(second)
	b, _ := json.Marshal(third)
	if string(a) != string(b) {
		t.Fatal("replay changed registry")
	}
	quiet, _ := Merge(second, Document{SchemaVersion: 1, Endpoints: []Endpoint{}}, "a", "s", "2026-10-11")
	c, _ := json.Marshal(quiet)
	if string(a) != string(c) {
		t.Fatal("quiet day lost state")
	}
}
func TestInvalidDocument(t *testing.T) {
	for _, s := range []string{`{}`, `{"schema_version":2,"endpoints":[]}`, `{"schema_version":1,"endpoints":[{"ip":"8.8.8.8"}]}`, `{"schema_version":1,"endpoints":[{"ip":"10.0.0.1","probe":{"targets":[{"protocol":"udp","port":22}]}}]}`} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
