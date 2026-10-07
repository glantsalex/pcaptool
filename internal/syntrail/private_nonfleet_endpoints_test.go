package syntrail

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWritePrivateNonFleetEndpointsJSONEmpty(t *testing.T) {
	var buffer bytes.Buffer
	if err := WritePrivateNonFleetEndpointsJSON(&buffer, nil, nil, time.Time{}); err != nil {
		t.Fatalf("WritePrivateNonFleetEndpointsJSON() error = %v", err)
	}

	want := "{\n  \"schema_version\": 1,\n  \"snapshot_time\": 0,\n  \"endpoints\": []\n}\n"
	if got := buffer.String(); got != want {
		t.Fatalf("WritePrivateNonFleetEndpointsJSON() = %q, want %q", got, want)
	}
}

func TestWritePrivateNonFleetEndpointsJSONAggregatesDistinctDevicesAndSorts(t *testing.T) {
	serverRecords := []Record{
		endpointRecord("10.20.0.1", "10.0.0.10", 1883, ProtocolTCP),
		endpointRecord("10.20.0.1", "10.0.0.10", 1883, Protocol("TCP")),
		endpointRecord("10.20.0.2", "10.0.0.10", 1883, ProtocolTCP),
		endpointRecord("10.20.0.1", "10.0.0.10", 443, ""),
		endpointRecord("10.20.0.1", "10.0.0.10", 53, ProtocolUDP),
		endpointRecord("10.20.0.2", "10.0.0.10", 53, ProtocolUDP),
		endpointRecord("10.20.0.3", "10.0.0.10", 53, Protocol("UDP")),
		endpointRecord("10.20.0.1", "10.0.0.10", 53, ProtocolTCP),
		endpointRecord("10.20.0.4", "10.0.0.20", 8443, ProtocolTCP),
	}
	probeRecords := []Record{
		endpointRecord("10.0.0.10", "10.30.0.1", 22, ProtocolTCP),
		endpointRecord("10.0.0.10", "10.30.0.1", 22, Protocol("TCP")),
		endpointRecord("10.0.0.10", "10.30.0.2", 22, ProtocolTCP),
		endpointRecord("10.0.0.10", "10.30.0.1", 8080, ""),
		endpointRecord("10.0.0.2", "10.30.0.1", 502, ProtocolTCP),
	}

	var buffer bytes.Buffer
	if err := WritePrivateNonFleetEndpointsJSON(&buffer, serverRecords, probeRecords, time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("WritePrivateNonFleetEndpointsJSON() error = %v", err)
	}

	var got PrivateNonFleetEndpointsDocument
	if err := json.Unmarshal(buffer.Bytes(), &got); err != nil {
		t.Fatalf("decode private non-fleet endpoints JSON: %v", err)
	}
	want := PrivateNonFleetEndpointsDocument{
		SchemaVersion: 1,
		SnapshotTime:  1790812800000,
		Endpoints: []PrivateNonFleetEndpoint{
			{
				IP:     "10.0.0.2",
				Server: ServerBehavior{Listeners: []TransportBehavior{}},
				Probe: ProbeBehavior{Targets: []TransportBehavior{
					{Protocol: "tcp", Port: 502, FleetDevicesCount: 1},
				}},
			},
			{
				IP: "10.0.0.10",
				Server: ServerBehavior{Listeners: []TransportBehavior{
					{Protocol: "tcp", Port: 53, FleetDevicesCount: 1},
					{Protocol: "udp", Port: 53, FleetDevicesCount: 3},
					{Protocol: "tcp", Port: 443, FleetDevicesCount: 1},
					{Protocol: "tcp", Port: 1883, FleetDevicesCount: 2},
				}},
				Probe: ProbeBehavior{Targets: []TransportBehavior{
					{Protocol: "tcp", Port: 22, FleetDevicesCount: 2},
					{Protocol: "tcp", Port: 8080, FleetDevicesCount: 1},
				}},
			},
			{
				IP: "10.0.0.20",
				Server: ServerBehavior{Listeners: []TransportBehavior{
					{Protocol: "tcp", Port: 8443, FleetDevicesCount: 1},
				}},
				Probe: ProbeBehavior{Targets: []TransportBehavior{}},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded document = %#v, want %#v", got, want)
	}
	if strings.Contains(buffer.String(), "null") {
		t.Fatalf("JSON contains null collection: %s", buffer.String())
	}
	for _, endpoint := range got.Endpoints {
		for _, behavior := range append(append([]TransportBehavior{}, endpoint.Server.Listeners...), endpoint.Probe.Targets...) {
			if behavior.FleetDevicesCount < 1 {
				t.Fatalf("endpoint %s behavior %#v has non-positive fleet_devices_count", endpoint.IP, behavior)
			}
		}
	}
}

func TestWritePrivateNonFleetEndpointsJSONReportsWriteFailure(t *testing.T) {
	err := WritePrivateNonFleetEndpointsJSON(failingWriter{}, nil, nil, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "encode private non-fleet endpoints JSON") {
		t.Fatalf("WritePrivateNonFleetEndpointsJSON() error = %v, want contextual encoding error", err)
	}
}

func TestWritePrivateNonFleetEndpointsJSONIgnoresNonIPv4Evidence(t *testing.T) {
	serverRecords := []Record{
		endpointRecord("10.20.0.1", "2001:db8::1", 443, ProtocolTCP),
		endpointRecord("2001:db8::2", "10.0.0.1", 443, ProtocolTCP),
	}

	var buffer bytes.Buffer
	if err := WritePrivateNonFleetEndpointsJSON(&buffer, serverRecords, nil, time.Time{}); err != nil {
		t.Fatalf("WritePrivateNonFleetEndpointsJSON() error = %v", err)
	}

	var got PrivateNonFleetEndpointsDocument
	if err := json.Unmarshal(buffer.Bytes(), &got); err != nil {
		t.Fatalf("decode private non-fleet endpoints JSON: %v", err)
	}
	if len(got.Endpoints) != 0 {
		t.Fatalf("endpoints = %#v, want empty for non-IPv4 evidence", got.Endpoints)
	}
}

func TestWritePrivateNonFleetEndpointsJSONSnapshotTime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first time.Time
		want  int64
	}{
		{name: "unknown", first: time.Time{}, want: 0},
		{name: "UTC midnight", first: time.UnixMilli(1790812800000), want: 1790812800000},
		{name: "example timestamp at 08 UTC", first: time.UnixMilli(1790841600000), want: 1790812800000},
		{name: "UTC afternoon with subseconds", first: time.UnixMilli(1790812800000).Add(15*time.Hour + 123456789*time.Nanosecond), want: 1790812800000},
		{name: "timezone crosses previous UTC day", first: time.Date(2026, 10, 2, 1, 0, 0, 0, time.FixedZone("UTC+3", 3*3600)), want: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixMilli()},
		{name: "timezone crosses next UTC year", first: time.Date(2026, 12, 31, 23, 0, 0, 0, time.FixedZone("UTC-3", -3*3600)), want: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()},
		{name: "leap day", first: time.Date(2024, 2, 29, 23, 59, 59, 999999999, time.UTC), want: 1709164800000},
		{name: "before Unix epoch", first: time.Unix(-1, 0), want: -86400000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := WritePrivateNonFleetEndpointsJSON(&buffer, nil, nil, tc.first); err != nil {
				t.Fatal(err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(buffer.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if len(document) != 3 {
				t.Fatalf("document keys = %v, want schema_version, snapshot_time, endpoints", document)
			}
			var got int64
			if bytes.Equal(bytes.TrimSpace(document["snapshot_time"]), []byte("null")) {
				t.Fatal("snapshot_time must not be null")
			}
			if err := json.Unmarshal(document["snapshot_time"], &got); err != nil {
				t.Fatalf("snapshot_time must be a present JSON integer: %v", err)
			}
			if got != tc.want {
				t.Fatalf("snapshot_time = %d, want %d", got, tc.want)
			}
		})
	}
}

func endpointRecord(srcIP, dstIP string, dstPort uint16, protocol Protocol) Record {
	return Record{
		SrcIP:    netip.MustParseAddr(srcIP),
		DstIP:    netip.MustParseAddr(dstIP),
		DstPort:  dstPort,
		Protocol: protocol,
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
