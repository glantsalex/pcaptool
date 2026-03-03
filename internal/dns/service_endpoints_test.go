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
			DestinationIP: "10.4.17.52", // private destination -> excluded
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
	}

	out := BuildServiceEndpoints(in)
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2; out=%#v", len(out), out)
	}

	if out[0].IP != "34.120.10.1" || out[0].DNS != "api.example.com" || out[0].Port != 443 {
		t.Fatalf("unexpected row0: %#v", out[0])
	}
	if out[0].ObservedAt != tsEarly.UnixMilli() {
		t.Fatalf("row0 observed_at=%d, want %d", out[0].ObservedAt, tsEarly.UnixMilli())
	}

	if out[1].IP != "34.120.10.1" || out[1].DNS != "api.example.com" || out[1].Port != 8443 {
		t.Fatalf("unexpected row1: %#v", out[1])
	}
}

func TestServiceEndpointHash64_Deterministic(t *testing.T) {
	h1 := serviceEndpointHash64("34.120.10.1", "api.example.com", 443)
	h2 := serviceEndpointHash64("34.120.10.1", "api.example.com", 443)
	if h1 != h2 {
		t.Fatalf("hash mismatch for same tuple: %d vs %d", h1, h2)
	}
	if h1 == serviceEndpointHash64("34.120.10.1", "api.example.com", 8443) {
		t.Fatalf("hash should differ when port differs")
	}
}
