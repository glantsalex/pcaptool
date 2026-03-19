package dns

import (
	"testing"
	"time"
)

func TestBuildServiceEndpoints_DedupAndEarliestObservedAt(t *testing.T) {
	tsLater := time.Date(2026, 3, 3, 13, 0, 2, 0, time.UTC)
	tsEarly := time.Date(2026, 3, 3, 13, 0, 1, 0, time.UTC)

	in := []TopologyEntry{
		{
			IssuerIP:      "10.1.1.1",
			DestinationIP: "34.120.10.1",
			DNSName:       "Api.Example.COM.",
			DNSSource:     "dns+conn+synack",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    tsLater,
		},
		{
			IssuerIP:      "10.1.1.2",
			DestinationIP: "34.120.10.1",
			DNSName:       "api.example.com",
			DNSSource:     "csv+mid",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    tsEarly,
		},
		{
			IssuerIP:      "10.1.1.3",
			DestinationIP: "34.120.10.1",
			DNSName:       "api.example.com",
			DNSSource:     "dns+conn+synack",
			Protocol:      "tcp",
			Port:          8443,
			ObservedAt:    tsLater,
		},
		{
			IssuerIP:      "10.1.1.4",
			DestinationIP: "10.4.17.52",
			DNSName:       "private.example.com",
			DNSSource:     "csv+mid",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    tsLater,
		},
		{
			IssuerIP:      "10.1.1.5",
			DestinationIP: "34.120.10.2",
			DNSName:       "", // unresolved -> excluded
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    tsLater,
		},
		{
			IssuerIP:      "100.110.233.120", // CGNAT/non-public -> should count as peer
			DestinationIP: "34.120.10.1",
			DNSName:       "api.example.com",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    tsLater,
		},
	}

	out := BuildServiceEndpoints(in)
	if len(out) != 4 {
		t.Fatalf("len(out)=%d, want 4; out=%#v", len(out), out)
	}

	if out[0].IP != "10.4.17.52" || out[0].DNS != "private.example.com" || out[0].Port != 443 {
		t.Fatalf("unexpected row0: %#v", out[0])
	}
	if out[0].Protocol != "tcp" {
		t.Fatalf("row0 protocol=%q, want tcp", out[0].Protocol)
	}
	if out[0].PeersCount != 1 {
		t.Fatalf("row0 peers_count=%d, want 1", out[0].PeersCount)
	}

	if out[1].IP != "34.120.10.1" || out[1].DNS != "api.example.com" || out[1].Port != 443 {
		t.Fatalf("unexpected row1: %#v", out[1])
	}
	if out[1].Protocol != "tcp" {
		t.Fatalf("row1 protocol=%q, want tcp", out[1].Protocol)
	}
	if out[1].PeersCount != 3 {
		t.Fatalf("row1 peers_count=%d, want 3", out[1].PeersCount)
	}
	if out[1].ObservedAt != tsEarly.UnixMilli() {
		t.Fatalf("row1 observed_at=%d, want %d", out[1].ObservedAt, tsEarly.UnixMilli())
	}

	if out[2].IP != "34.120.10.1" || out[2].DNS != "api.example.com" || out[2].Port != 8443 {
		t.Fatalf("unexpected row2: %#v", out[2])
	}
	if out[2].Protocol != "tcp" {
		t.Fatalf("row2 protocol=%q, want tcp", out[2].Protocol)
	}
	if out[2].PeersCount != 1 {
		t.Fatalf("row2 peers_count=%d, want 1", out[2].PeersCount)
	}

	if out[3].IP != "34.120.10.2" || out[3].DNS != serviceEndpointNoDNSAttribution || out[3].Port != 443 {
		t.Fatalf("unexpected row3: %#v", out[3])
	}
	if out[3].Protocol != "tcp" {
		t.Fatalf("row3 protocol=%q, want tcp", out[3].Protocol)
	}
	if out[3].PeersCount != 1 {
		t.Fatalf("row3 peers_count=%d, want 1", out[3].PeersCount)
	}
}

func TestBuildServiceEndpoints_SyntheticDNSOnlyWhenNoRealDNSExists(t *testing.T) {
	ts := time.Date(2026, 3, 3, 13, 0, 1, 0, time.UTC)
	in := []TopologyEntry{
		{
			IssuerIP:      "10.1.1.1",
			DestinationIP: "10.4.17.52",
			DNSName:       "",
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          1883,
			ObservedAt:    ts,
		},
		{
			IssuerIP:      "10.1.1.2",
			DestinationIP: "10.4.17.52",
			DNSName:       "",
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          1883,
			ObservedAt:    ts,
		},
		{
			IssuerIP:      "10.1.1.3",
			DestinationIP: "34.120.10.10",
			DNSName:       "api.example.com",
			DNSSource:     "dns+synack",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    ts,
		},
		{
			IssuerIP:      "10.1.1.4",
			DestinationIP: "34.120.10.10",
			DNSName:       "",
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          443,
			ObservedAt:    ts,
		},
	}

	out := BuildServiceEndpoints(in)
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2; out=%#v", len(out), out)
	}
	if out[0].IP != "10.4.17.52" || out[0].DNS != serviceEndpointPrivateServer {
		t.Fatalf("unexpected synthetic private row: %#v", out[0])
	}
	if out[0].PeersCount != 2 {
		t.Fatalf("private synthetic peers_count=%d, want 2", out[0].PeersCount)
	}
	if out[1].IP != "34.120.10.10" || out[1].DNS != "api.example.com" {
		t.Fatalf("unexpected public row: %#v", out[1])
	}
}

func TestServiceEndpointHash64_Deterministic(t *testing.T) {
	h1 := serviceEndpointHash64("34.120.10.1", "api.example.com", "tcp", 443)
	h2 := serviceEndpointHash64("34.120.10.1", "api.example.com", "tcp", 443)
	if h1 != h2 {
		t.Fatalf("hash mismatch for same tuple: %d vs %d", h1, h2)
	}
	if h1 == serviceEndpointHash64("34.120.10.1", "api.example.com", "tcp", 8443) {
		t.Fatalf("hash should differ when port differs")
	}
	if h1 == serviceEndpointHash64("34.120.10.1", "api.example.com", "udp", 443) {
		t.Fatalf("hash should differ when protocol differs")
	}
}
