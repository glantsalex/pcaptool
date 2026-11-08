package logicalservice

import (
	"context"
	"strings"
	"testing"
)

func TestMixedSelectorsAndBoundTransports(t *testing.T) {
	classifier := classifierForMatch(t, `dns_exact: [api.example.com]
      dns_suffix: [example.com]
      dns_contains: [special]
      dns_regex: ['^other[0-9]+\.invalid$']
      transports:
        - proto: tcp
          ports: [80, 443]
        - proto: udp
          ports: [443]`)
	for _, tc := range []struct {
		dns, proto string
		port       uint16
		want       bool
	}{
		{"api.example.com", "tcp", 443, true}, // Overlapping selectors are one rule.
		{"new.example.com", "tcp", 80, true},
		{"other12.invalid", "udp", 443, true},
		{"a-special.invalid", "tcp", 443, true},
		{"api.example.com", "udp", 80, false}, // No transport cross-product.
		{"notexample.com", "tcp", 443, false},
		{"api.example.com.evil.invalid", "tcp", 443, false},
		{"other12.invalid.evil.invalid", "tcp", 443, false},
		{"", "tcp", 443, false},
	} {
		result, err := classifier.Classify(context.Background(), []Endpoint{{DNS: tc.dns, Protocol: tc.proto, DstPort: tc.port}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Entries[0].Matched != tc.want {
			t.Fatalf("%+v: got %+v", tc, result)
		}
	}
}

func TestRejectLegacyAndInvalidTransports(t *testing.T) {
	for _, match := range []string{
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
		"dns_exact: [api.example.com]\n      transports: []",
		"dns_exact: [api.example.com]\n      transports:\n        - proto: tcp\n          ports: [443]\n        - proto: TCP\n          ports: [80]",
		"dns_exact: [api.example.com]\n      transports:\n        - proto: tcp\n          any_port: true",
		"dns_exact: [api.example.com]\n      dns_regex: ['[']\n      transports:\n        - proto: tcp\n          ports: [443]",
	} {
		catalog := loadCatalogYAML(t, validCatalogYAML)
		path := writeTestFile(t, "rules.yaml", ruleYAML("test", "100", "example_service", match))
		if _, err := LoadRules(path, catalog); err == nil {
			t.Fatalf("accepted invalid match: %s", match)
		}
	}
}

func TestDefinitionsLoader(t *testing.T) {
	yaml := validCatalogYAML + strings.TrimPrefix(ruleYAML("test", "100", "example_service",
		"dns_suffix: [example.com]\n      transports:\n        - proto: tcp\n          ports: [443]"), "schema_version: 1\n")
	d, err := LoadDefinitions(writeTestFile(t, "definitions.yaml", yaml))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Classifier(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadDefinitions(writeTestFile(t, "invalid.yaml", yaml+"\nlegacy: true\n"))
	if err == nil {
		t.Fatal("unknown top-level field accepted")
	}
}

func TestCombinedDefinitionsExample(t *testing.T) {
	d, err := LoadDefinitions("../../configs/logical-services-definitions.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Classifier()
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Classify(context.Background(), []Endpoint{
		{DNS: "router15.teamviewer.com", Protocol: "tcp", DstPort: 5938},
		{DNS: "gridx-de-ds-production-vpnctl.s3.eu-central-1.amazonaws.com", Protocol: "tcp", DstPort: 443},
	})
	if err != nil || !result.Entries[0].Matched || !result.Entries[1].Matched {
		t.Fatalf("example classifications: %+v %v", result, err)
	}
}
