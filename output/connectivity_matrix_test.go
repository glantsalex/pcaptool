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
	"reflect"
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

type compactTopologyTestPayload struct {
	Version  int                                    `json:"version"`
	Layout   string                                 `json:"layout"`
	TimeUnit string                                 `json:"time_unit"`
	Columns  []string                               `json:"columns"`
	Dict     networkTopologyMatrixCompactDictionary `json:"dict"`
	Issuers  []json.RawMessage                      `json:"issuers"`
}

type compactTopologyTestIssuer struct {
	ID   int64
	Rows [][6]int64
}

func TestWriteNetworkTopologyMatrixCompactJSONSingle(t *testing.T) {
	observedAt := time.Date(2026, 7, 2, 11, 22, 33, 456789123, time.FixedZone("test", 2*60*60))
	entries := []dns.TopologyEntry{{
		IssuerIP:      "10.0.0.1",
		DestinationIP: "203.0.113.10",
		DNSName:       "api.example.com",
		DNSSource:     "dns+synack",
		Protocol:      "tcp",
		Port:          443,
		ObservedAt:    observedAt,
	}}

	payload, issuers, _ := writeAndDecodeCompactTopology(t, entries)
	if payload.Version != 2 || payload.Layout != "dict_by_issuer" || payload.TimeUnit != "unix_ms" {
		t.Fatalf("metadata = version %d, layout %q, time unit %q", payload.Version, payload.Layout, payload.TimeUnit)
	}
	wantColumns := []string{"dst", "dns", "source", "proto", "port", "first_ms"}
	if !reflect.DeepEqual(payload.Columns, wantColumns) {
		t.Fatalf("columns = %#v, want %#v", payload.Columns, wantColumns)
	}
	if !reflect.DeepEqual(payload.Dict.Issuer, []string{"10.0.0.1"}) ||
		!reflect.DeepEqual(payload.Dict.Dst, []string{"203.0.113.10"}) ||
		!reflect.DeepEqual(payload.Dict.DNS, []string{"api.example.com"}) ||
		!reflect.DeepEqual(payload.Dict.Source, []string{"dns+synack"}) ||
		!reflect.DeepEqual(payload.Dict.Proto, []string{"tcp"}) {
		t.Fatalf("unexpected dictionaries: %#v", payload.Dict)
	}
	wantIssuers := []compactTopologyTestIssuer{{
		ID:   0,
		Rows: [][6]int64{{0, 0, 0, 0, 443, observedAt.UTC().UnixMilli()}},
	}}
	if !reflect.DeepEqual(issuers, wantIssuers) {
		t.Fatalf("issuers = %#v, want %#v", issuers, wantIssuers)
	}
}

func TestWriteNetworkTopologyMatrixCompactJSONGroupsDeduplicatesAndPreservesEmptyValues(t *testing.T) {
	entries := []dns.TopologyEntry{
		{IssuerIP: "issuer-a", DestinationIP: "dst-1", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 80},
		{IssuerIP: "issuer-b", DestinationIP: "dst-2", DNSName: "name.example", DNSSource: "dns", Protocol: "udp", Port: 53},
		{IssuerIP: "issuer-a", DestinationIP: "dst-2", DNSName: "", DNSSource: "", Protocol: "tcp", Port: 443},
	}

	payload, issuers, _ := writeAndDecodeCompactTopology(t, entries)
	wantDict := networkTopologyMatrixCompactDictionary{
		Issuer: []string{"issuer-a", "issuer-b"},
		Dst:    []string{"dst-1", "dst-2"},
		DNS:    []string{"", "name.example"},
		Source: []string{"", "dns"},
		Proto:  []string{"tcp", "udp"},
	}
	if !reflect.DeepEqual(payload.Dict, wantDict) {
		t.Fatalf("dict = %#v, want %#v", payload.Dict, wantDict)
	}
	wantIssuers := []compactTopologyTestIssuer{
		{ID: 0, Rows: [][6]int64{{0, 0, 0, 0, 80, 0}, {1, 0, 0, 0, 443, 0}}},
		{ID: 1, Rows: [][6]int64{{1, 1, 1, 1, 53, 0}}},
	}
	if !reflect.DeepEqual(issuers, wantIssuers) {
		t.Fatalf("issuer groups = %#v, want %#v", issuers, wantIssuers)
	}
}

func TestWriteNetworkTopologyMatrixCompactJSONEmpty(t *testing.T) {
	payload, issuers, encoded := writeAndDecodeCompactTopology(t, nil)
	if !reflect.DeepEqual(payload.Dict, networkTopologyMatrixCompactDictionary{
		Issuer: []string{}, Dst: []string{}, DNS: []string{}, Source: []string{}, Proto: []string{},
	}) {
		t.Fatalf("empty dict = %#v, want empty arrays", payload.Dict)
	}
	if issuers == nil || len(issuers) != 0 {
		t.Fatalf("empty issuers = %#v, want non-nil empty array", issuers)
	}
	if bytes.Contains(encoded, []byte("null")) {
		t.Fatalf("empty payload contains null instead of arrays: %s", encoded)
	}
}

func TestWriteNetworkTopologyMatrixCompactJSONDeterministic(t *testing.T) {
	entries := []dns.TopologyEntry{
		{IssuerIP: "issuer-b", DestinationIP: "dst-2", DNSName: "b.example", DNSSource: "csv+mid", Protocol: "tcp", Port: 443},
		{IssuerIP: "issuer-a", DestinationIP: "dst-1", DNSName: "a.example", DNSSource: "dns+synack", Protocol: "udp", Port: 53},
	}

	_, _, first := writeAndDecodeCompactTopology(t, entries)
	_, _, second := writeAndDecodeCompactTopology(t, entries)
	if !bytes.Equal(first, second) {
		t.Fatalf("encoding is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestWriteNetworkTopologyMatrixCompactJSONRoundTripAtMillisecondPrecision(t *testing.T) {
	entries := []dns.TopologyEntry{
		{
			IssuerIP: "issuer-a", DestinationIP: "dst-1", DNSName: "a.example", DNSSource: "dns",
			Protocol: "tcp", Port: 443, ObservedAt: time.Date(2026, 7, 2, 1, 2, 3, 987654321, time.UTC),
		},
		{
			IssuerIP: "issuer-b", DestinationIP: "dst-2", DNSName: "", DNSSource: "",
			Protocol: "udp", Port: 53,
		},
	}

	payload, issuers, _ := writeAndDecodeCompactTopology(t, entries)
	var reconstructed []dns.TopologyEntry
	for _, issuer := range issuers {
		for _, row := range issuer.Rows {
			entry := dns.TopologyEntry{
				IssuerIP:      payload.Dict.Issuer[issuer.ID],
				DestinationIP: payload.Dict.Dst[row[0]],
				DNSName:       payload.Dict.DNS[row[1]],
				DNSSource:     payload.Dict.Source[row[2]],
				Protocol:      payload.Dict.Proto[row[3]],
				Port:          uint16(row[4]),
			}
			if row[5] != 0 {
				entry.ObservedAt = time.UnixMilli(row[5]).UTC()
			}
			reconstructed = append(reconstructed, entry)
		}
	}

	if len(reconstructed) != len(entries) {
		t.Fatalf("round trip entry count = %d, want %d", len(reconstructed), len(entries))
	}
	for i := range entries {
		want := entries[i]
		if !want.ObservedAt.IsZero() {
			want.ObservedAt = time.UnixMilli(want.ObservedAt.UTC().UnixMilli()).UTC()
		}
		if !reflect.DeepEqual(reconstructed[i], want) {
			t.Fatalf("round trip entry %d = %#v, want %#v", i, reconstructed[i], want)
		}
	}
}

func writeAndDecodeCompactTopology(t *testing.T, entries []dns.TopologyEntry) (compactTopologyTestPayload, []compactTopologyTestIssuer, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteNetworkTopologyMatrixCompactJSON(&buf, entries); err != nil {
		t.Fatalf("WriteNetworkTopologyMatrixCompactJSON() error = %v", err)
	}

	var payload compactTopologyTestPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\npayload: %s", err, buf.Bytes())
	}
	issuers := make([]compactTopologyTestIssuer, 0, len(payload.Issuers))
	for i, rawGroup := range payload.Issuers {
		var parts []json.RawMessage
		if err := json.Unmarshal(rawGroup, &parts); err != nil {
			t.Fatalf("unmarshal issuer group %d: %v", i, err)
		}
		if len(parts) != 2 {
			t.Fatalf("issuer group %d has %d elements, want 2", i, len(parts))
		}
		var group compactTopologyTestIssuer
		if err := json.Unmarshal(parts[0], &group.ID); err != nil {
			t.Fatalf("unmarshal issuer ID %d: %v", i, err)
		}
		if err := json.Unmarshal(parts[1], &group.Rows); err != nil {
			t.Fatalf("unmarshal issuer rows %d: %v", i, err)
		}
		issuers = append(issuers, group)
	}
	return payload, issuers, append([]byte(nil), buf.Bytes()...)
}
