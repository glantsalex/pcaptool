package dns

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestPublicUnresolvedDestinationEndpoints(t *testing.T) {
	ts := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	in := []TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "159.69.94.54", Protocol: "tcp", Port: 443, ObservedAt: ts},
		{IssuerIP: "10.0.0.2", DestinationIP: "159.69.94.54", Protocol: "tcp", Port: 443, ObservedAt: ts.Add(time.Second)},
		{IssuerIP: "10.0.0.3", DestinationIP: "159.69.94.54", Protocol: "udp", Port: 53, ObservedAt: ts},
		{IssuerIP: "10.0.0.4", DestinationIP: "10.1.1.1", Protocol: "tcp", Port: 443, ObservedAt: ts},
		{IssuerIP: "10.0.0.5", DestinationIP: "159.69.94.54", DNSName: "example.com", Protocol: "tcp", Port: 443, ObservedAt: ts},
	}

	got := PublicUnresolvedDestinationEndpoints(in)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].IP != "159.69.94.54" || got[0].Port != 443 || got[0].Proto != "tcp" || got[0].Count != 2 {
		t.Fatalf("got[0] = %+v", got[0])
	}
	if got[1].IP != "159.69.94.54" || got[1].Port != 53 || got[1].Proto != "udp" || got[1].Count != 1 {
		t.Fatalf("got[1] = %+v", got[1])
	}
}

func TestWriteUnresolvedIPEndpointsJSON(t *testing.T) {
	entries := []UnresolvedIPEndpoint{
		{IP: "159.69.94.54", Port: 443, Proto: "tcp", Count: 2},
	}

	var buf bytes.Buffer
	if err := WriteUnresolvedIPEndpointsJSON(&buf, entries); err != nil {
		t.Fatalf("WriteUnresolvedIPEndpointsJSON() error = %v", err)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("len(decoded) = %d, want 1", len(decoded))
	}
	if decoded[0]["ip"] != "159.69.94.54" {
		t.Fatalf("ip = %v", decoded[0]["ip"])
	}
	if decoded[0]["proto"] != "tcp" {
		t.Fatalf("proto = %v", decoded[0]["proto"])
	}
	if decoded[0]["count"] != float64(2) {
		t.Fatalf("count = %v", decoded[0]["count"])
	}
}
