// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
)

func TestWriteNetworkTopologyMatrixJSON(t *testing.T) {
	entries := []dns.TopologyEntry{
		{
			IssuerIP:      "10.4.100.58",
			DestinationIP: "100.104.10.1",
			DNSName:       "",
			DNSSource:     "mid-session",
			Protocol:      "tcp",
			Port:          22,
			ObservedAt:    time.Date(2026, 4, 13, 10, 15, 0, 123456789, time.UTC),
		},
		{
			IssuerIP:      "10.119.75.23",
			DestinationIP: "153.46.100.66",
			DNSName:       "ep2.online-log.worldline.ch",
			DNSSource:     "csv+mid",
			Protocol:      "tcp",
			Port:          51003,
		},
	}

	var buf bytes.Buffer
	if err := WriteNetworkTopologyMatrixJSON(&buf, entries); err != nil {
		t.Fatalf("WriteNetworkTopologyMatrixJSON() error = %v", err)
	}

	var got struct {
		Version int `json:"version"`
		Entries []struct {
			IssuerIP      string `json:"issuer_ip"`
			DestinationIP string `json:"destination_ip"`
			DNSName       string `json:"dns_name"`
			DNSSource     string `json:"dns_source"`
			Protocol      string `json:"protocol"`
			Port          uint16 `json:"port"`
			ObservedAtUTC string `json:"observed_at_utc"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Version)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(got.Entries))
	}
	if got.Entries[0].IssuerIP != "10.4.100.58" || got.Entries[0].DestinationIP != "100.104.10.1" {
		t.Fatalf("first entry = %+v", got.Entries[0])
	}
	if got.Entries[0].ObservedAtUTC != "2026-04-13T10:15:00.123456789Z" {
		t.Fatalf("observed_at_utc = %q", got.Entries[0].ObservedAtUTC)
	}
	if got.Entries[1].DNSName != "ep2.online-log.worldline.ch" || got.Entries[1].DNSSource != "csv+mid" {
		t.Fatalf("second entry = %+v", got.Entries[1])
	}
}
