package dns

import (
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

func TestAllowConnectionInferredDNSBackfillWithCSVGuard(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		ip        string
		ipToDNS   map[string][]string
		wantAllow bool
		wantCSV   string
	}{
		{
			name:      "no csv keeps current inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			wantAllow: true,
		},
		{
			name:      "ip absent keeps current inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.53": {"api.store.ccv.eu"}},
			wantAllow: true,
		},
		{
			name:      "same csv dns confirms inference",
			candidate: "api.store.ccv.eu.",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.52": {"API.Store.CCV.EU"}},
			wantAllow: true,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "single different csv dns suppresses inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.52": {"api.store.ccv.eu"}},
			wantAllow: false,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "multi csv containing candidate allows inference",
			candidate: "api.store.ccv.eu",
			ip:        "18.244.102.52",
			ipToDNS: map[string][]string{"18.244.102.52": {
				"mpush.store.ccv.eu",
				"api.store.ccv.eu",
			}},
			wantAllow: true,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "multi csv without candidate suppresses inference without choosing dns",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS: map[string][]string{"18.244.102.52": {
				"mpush.store.ccv.eu",
				"api.store.ccv.eu",
			}},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllow, gotCSV := allowConnectionInferredDNSBackfill(tt.candidate, tt.ip, tt.ipToDNS)
			if gotAllow != tt.wantAllow || gotCSV != tt.wantCSV {
				t.Fatalf("allowConnectionInferredDNSBackfill() = (%v, %q), want (%v, %q)", gotAllow, gotCSV, tt.wantAllow, tt.wantCSV)
			}
		})
	}
}

func TestSuppressMergedFTPPassiveEdges(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 49824, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 50081, FirstSeen: ts.Add(2 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 1882, FirstSeen: ts.Add(3 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 6915, FirstSeen: ts.Add(4 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(edges, connectivity.DefaultOptions().FTPPassiveMinPort, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 edges after ftp passive suppression, got %#v", got)
	}
	if got[0].Port != 21 || got[1].Port != 1882 || got[2].Port != 6915 {
		t.Fatalf("expected ports 21, 1882, 6915 after suppression, got %#v", got)
	}
}

func TestSuppressMergedFTPPassiveEdgesCustomControlPort(t *testing.T) {
	ts := time.Unix(1700000100, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21000, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 49824, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts.Add(2 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 50081, FirstSeen: ts.Add(3 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(
		edges,
		connectivity.DefaultOptions().FTPPassiveMinPort,
		map[uint16]struct{}{21000: {}},
	)
	if len(got) != 3 {
		t.Fatalf("expected custom control suppression only, got %#v", got)
	}
	if got[0].Port != 21000 || got[1].Port != 21 || got[2].Port != 50081 {
		t.Fatalf("expected ports 21000, 21, 50081 after suppression, got %#v", got)
	}
}

func TestSuppressMergedFTPPassiveEdgesUsesConfiguredMinimum(t *testing.T) {
	tests := []struct {
		name           string
		minPassivePort uint16
		wantDataEdge   bool
	}{
		{name: "custom lower minimum suppresses data edge", minPassivePort: 16000},
		{name: "data edge below custom minimum is retained", minPassivePort: 17000, wantDataEdge: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := time.Unix(1700000200, 0).UTC()
			edges := []connectivity.Edge{
				{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21000, FirstSeen: ts},
				{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 16279, FirstSeen: ts.Add(time.Second)},
			}

			got := suppressMergedFTPPassiveEdges(
				edges,
				tt.minPassivePort,
				map[uint16]struct{}{21000: {}},
			)
			wantEdges := 1
			if tt.wantDataEdge {
				wantEdges = 2
			}
			if len(got) != wantEdges {
				t.Fatalf("expected %d edges, got %#v", wantEdges, got)
			}
			gotPorts := make(map[uint16]struct{}, len(got))
			for _, edge := range got {
				gotPorts[edge.Port] = struct{}{}
			}
			if _, ok := gotPorts[21000]; !ok {
				t.Fatalf("expected custom control edge, got %#v", got)
			}
			_, gotDataEdge := gotPorts[16279]
			if gotDataEdge != tt.wantDataEdge {
				t.Fatalf("expected below-threshold data edge, got %#v", got)
			}
		})
	}
}

func TestSuppressMergedFTPPassiveEdgesZeroMinimumUsesDefault(t *testing.T) {
	ts := time.Unix(1700000300, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 29999, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 30000, FirstSeen: ts.Add(2 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(edges, 0, nil)
	if len(got) != 2 {
		t.Fatalf("expected default minimum suppression, got %#v", got)
	}
	if got[0].Port != 21 || got[1].Port != 29999 {
		t.Fatalf("expected ports 21 and 29999 after suppression, got %#v", got)
	}
}
