package dns

import "testing"

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
