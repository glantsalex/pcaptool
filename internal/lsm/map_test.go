package lsm

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/logicalservice"
)

func testDefinitions(t *testing.T) *logicalservice.Definitions {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	err := os.WriteFile(path, []byte(`schema_version: 1
services:
  - id: platform
    name: Platform
rules:
  - id: platform_rule
    priority: 100
    service_id: platform
    match:
      dns_exact: [api.example.com]
      dns_suffix: [example.com]
      transports:
        - proto: tcp
          ports: [80, 443]
        - proto: udp
          ports: [443]
`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	d, err := logicalservice.LoadDefinitions(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPublicDestination(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "192.0.0.9", "192.0.0.10", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:3::1"} {
		if !PublicDestination(netip.MustParseAddr(s)) {
			t.Errorf("public rejected: %s", s)
		}
	}
	for _, s := range []string{"0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "172.16.0.1",
		"192.168.0.1", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"255.255.255.255", "::", "::1", "::ffff:10.0.0.1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "2002::1", "3fff::1", "64:ff9b::808:808"} {
		if PublicDestination(netip.MustParseAddr(s)) {
			t.Errorf("non-public admitted: %s", s)
		}
	}
	if PublicDestination(netip.Addr{}) {
		t.Fatal("invalid admitted")
	}
}

func TestBuildMapsPreservesObservationsAndFilters(t *testing.T) {
	d := testDefinitions(t)
	observed := time.Date(2026, 10, 10, 12, 30, 45, 123999999, time.FixedZone("offset", 3600))
	row := dns.TopologyEntry{IssuerIP: "10.1.1.1", DestinationIP: "8.8.8.8", DNSName: "api.example.com", Protocol: "tcp", Port: 443, ObservedAt: observed,
		ObservedDNSName: "raw.example.com", NormalizedDNSName: "api.example.com", NormalizationRuleID: "normalize", CNAMEChain: "raw -> api"}
	unknown := row
	unknown.DNSName = ""
	unknown.DestinationIP = "1.1.1.1"
	private := row
	private.IssuerIP = "10.2.2.2"
	private.DestinationIP = "10.4.17.52"
	cross := row
	cross.Protocol = "udp"
	cross.Port = 80
	rows := []dns.TopologyEntry{row, unknown, private, row, cross}
	before := append([]dns.TopologyEntry(nil), rows...)
	m, stats, err := Build(context.Background(), rows, d, "stream", "2026-10-10")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows, before) {
		t.Fatal("input mutated")
	}
	if stats.Public != 4 || stats.Classified != 2 || stats.Excluded != 1 || stats.Unclassified != 2 || stats.Issuers != 1 {
		t.Fatalf("stats %+v", stats)
	}
	if len(m.Devices[0].Services[0].Endpoints) != 2 {
		t.Fatal("duplicates removed")
	}
	if got := m.Devices[0].Services[0].Endpoints[0].SeenAt; got != "2026-10-10T11:30:45.123Z" {
		t.Fatal(got)
	}
	c, err := m.Compact()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var serialized CompactMap
	if err := json.Unmarshal(b, &serialized); err != nil {
		t.Fatal(err)
	}
	decoded, err := serialized.Expand()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, decoded) {
		t.Fatalf("round trip mismatch\n%+v\n%+v", m, decoded)
	}
	short := m.Short()
	if len(short) != 1 || len(short[0].Services) != 1 || short[0].Services[0].Port != 443 {
		t.Fatalf("short %+v", short)
	}
	// Same observations in a different traversal order have identical output.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	second, _, err := Build(context.Background(), rows, d, "stream", "2026-10-10")
	if err != nil || !reflect.DeepEqual(m, second) {
		t.Fatalf("non-deterministic: %v", err)
	}
	for _, bad := range []*int{nil, intPtr(-1), intPtr(999999)} {
		copyMap := c
		copyMap.Devices = append([]CompactDevice(nil), c.Devices...)
		copyMap.Devices[0].Issuer = bad
		if _, err := copyMap.Expand(); err == nil {
			t.Fatalf("invalid issuer reference accepted: %v", bad)
		}
	}
}
func intPtr(n int) *int { return &n }

func TestEmptyAndFailureCases(t *testing.T) {
	d := testDefinitions(t)
	m, stats, err := Build(context.Background(), nil, d, "stream", "unknown")
	if err != nil || stats.Public != 0 || m.Devices == nil {
		t.Fatalf("%+v %+v %v", m, stats, err)
	}
	c, err := m.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := c.Expand(); err != nil || !reflect.DeepEqual(decoded, m) {
		t.Fatal("empty roundtrip", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Build(ctx, nil, d, "stream", "unknown"); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, _, err := Build(context.Background(), []dns.TopologyEntry{{DestinationIP: "invalid"}}, d, "stream", "unknown"); err == nil {
		t.Fatal("invalid IP ignored")
	}
	rule := d.Rules[0]
	rule.ID = "conflict"
	d.Rules = append(d.Rules, rule)
	rows := []dns.TopologyEntry{{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "api.example.com", Protocol: "tcp", Port: 443}}
	var conflict *logicalservice.ConflictError
	if _, _, err := Build(context.Background(), rows, d, "stream", "unknown"); !errors.As(err, &conflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestUnclassifiedOnlyIssuerAndInvalidIssuer(t *testing.T) {
	d := testDefinitions(t)
	rows := []dns.TopologyEntry{{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443}}
	m, stats, err := Build(context.Background(), rows, d, "stream", "unknown")
	if err != nil || stats.Issuers != 1 || len(m.Devices) != 1 {
		t.Fatalf("missing unmatched issuer: %+v %v", stats, err)
	}
	if len(m.Devices[0].Services) != 0 || len(m.Devices[0].Unclassified) != 1 || len(m.Short()[0].Services) != 0 {
		t.Fatal("unmatched issuer must have an empty services list")
	}
	rows[0].IssuerIP = ""
	if _, _, err := Build(context.Background(), rows, d, "stream", "unknown"); err == nil {
		t.Fatal("missing issuer accepted")
	}
}

func TestCompactRejectsMalformedReferences(t *testing.T) {
	m, _, err := Build(context.Background(), []dns.TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", DNSName: "api.example.com", Protocol: "tcp", Port: 443},
	}, testDefinitions(t), "stream", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*CompactMap)
	}{
		{"missing destination", func(c *CompactMap) { c.Devices[0].Services[0].Endpoints[0].IP = nil }},
		{"invalid destination", func(c *CompactMap) { c.Devices[0].Services[0].Endpoints[0].IP = intPtr(-1) }},
		{"invalid DNS", func(c *CompactMap) { c.Devices[0].Services[0].Endpoints[0].DNS = intPtr(999) }},
		{"invalid rule", func(c *CompactMap) { c.Devices[0].Services[0].Endpoints[0].Rule = intPtr(999) }},
		{"missing service", func(c *CompactMap) { c.Devices[0].Services[0].Service = nil }},
		{"invalid service", func(c *CompactMap) { c.Devices[0].Services[0].Service = intPtr(999) }},
		{"duplicate dictionary", func(c *CompactMap) { c.Dictionaries.IPs = append(c.Dictionaries.IPs, c.Dictionaries.IPs[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := m.Compact()
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&c)
			if _, err := c.Expand(); err == nil {
				t.Fatal("invalid compact map accepted")
			}
		})
	}
}
