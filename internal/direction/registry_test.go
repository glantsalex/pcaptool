package direction

import (
	"encoding/json"
	"reflect"
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

func TestMergeUDPRolesAcrossDays(t *testing.T) {
	const early, late = "2026-11-15", "2026-11-17"
	registry := Document{SchemaVersion: Version, AccountID: "a", StreamID: "s"}
	daily := func(label string) Document {
		return Document{Endpoints: []Endpoint{{IP: "10.61.8.71",
			Server: Server{Listeners: []Behavior{
				{Protocol: "udp", Port: 161}, {Protocol: "udp", Port: 162, Evidence: label},
				{Protocol: "udp", Port: 1194}, {Protocol: "udp", Port: 49153},
			}},
			Probe: Probe{Targets: []Behavior{{Protocol: "udp", Port: 161}}},
		}}}
	}
	merge := func(old, d Document, day string) Document {
		t.Helper()
		got, err := Merge(old, d, "a", "s", day)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	labeled, unlabeled := daily("syslog"), daily("")
	forward := merge(merge(registry, labeled, early), unlabeled, late)
	backfill := merge(merge(registry, unlabeled, late), labeled, early)
	replay := merge(backfill, unlabeled, late)
	want := []Endpoint{{IP: "10.61.8.71",
		Server: Server{Listeners: []Behavior{
			{Protocol: "udp", Port: 162, Evidence: "syslog", FirstSeen: early, LastSeen: late},
			{Protocol: "udp", Port: 1194, FirstSeen: early, LastSeen: late},
		}},
		Probe: Probe{Targets: []Behavior{{Protocol: "udp", Port: 161, FirstSeen: early, LastSeen: late}}},
	}}
	for _, got := range []Document{forward, backfill, replay} {
		if err := got.ValidateRegistry("a", "s"); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Endpoints, want) {
			t.Fatalf("endpoints = %+v, want %+v", got.Endpoints, want)
		}
	}
}

func TestRegistryRejectsUnqualifiedRoles(t *testing.T) {
	for _, tc := range []struct {
		role     Role
		behavior Behavior
	}{
		{ListenerRole, Behavior{Protocol: "udp", Port: 161}},
		{ListenerRole, Behavior{Protocol: "udp", Port: 49153}},
		{ProbeRole, Behavior{Protocol: "udp", Port: 162}},
		{ProbeRole, Behavior{Protocol: "udp", Port: 1194}},
		{ProbeRole, Behavior{Protocol: "udp", Port: 161, Evidence: "syslog"}},
		{ListenerRole, Behavior{Protocol: "tcp", Port: 22}},
	} {
		b := tc.behavior
		b.FirstSeen, b.LastSeen = "2026-11-17", "2026-11-17"
		e := Endpoint{IP: "10.61.8.71"}
		if tc.role == ListenerRole {
			e.Server.Listeners = []Behavior{b}
		} else {
			e.Probe.Targets = []Behavior{b}
		}
		d := Document{SchemaVersion: Version, AccountID: "a", StreamID: "s", Endpoints: []Endpoint{e}}
		if err := d.ValidateRegistry("a", "s"); err == nil {
			t.Errorf("accepted %s %+v", tc.role, b)
		}
	}
}
