// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const twoServiceCatalogYAML = `
schema_version: 1
services:
  - id: service_one
    name: Service One
  - id: service_two
    name: Service Two
`

func TestNewClassifierCompilesImmutableState(t *testing.T) {
	rulesYAML := ruleYAML(
		"regex_rule",
		"300",
		"example_service",
		"dns_regex: ['api\\.example\\.com']\n      protocol: tcp\n      ports: [443]",
	) +
		ruleBody(
			"cidr_rule",
			"200",
			"example_service",
			"dst_ip_cidrs: [192.0.2.0/24]\n      protocol: udp\n      any_port: true",
		) +
		ruleBody(
			"exact_later_id",
			"100",
			"example_service",
			"dns_exact: [later.example.com]\n      protocol: tcp\n      ports: [443, 8443]",
		) +
		ruleBody(
			"exact_earlier_id",
			"100",
			"example_service",
			"dns_exact: [earlier.example.com]\n      protocol: tcp\n      ports: [443]",
		)
	catalog, rules := loadClassifierModels(t, validCatalogYAML, rulesYAML)
	controlCatalog, controlRules := loadClassifierModels(t, validCatalogYAML, rulesYAML)

	classifier, err := NewClassifier(catalog, rules)
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}
	if !reflect.DeepEqual(catalog, controlCatalog) {
		t.Fatal("NewClassifier() mutated the catalog")
	}
	if !reflect.DeepEqual(rules, controlRules) {
		t.Fatal("NewClassifier() mutated the rules")
	}

	tcpRules := classifier.rulesByProtocol["tcp"]
	udpRules := classifier.rulesByProtocol["udp"]
	if got := compiledRuleIDs(tcpRules); !reflect.DeepEqual(got, []string{"exact_earlier_id", "exact_later_id", "regex_rule"}) {
		t.Fatalf("TCP rule order = %v", got)
	}
	if got := compiledRuleIDs(udpRules); !reflect.DeepEqual(got, []string{"cidr_rule"}) {
		t.Fatalf("UDP rule order = %v", got)
	}
	if tcpRules[2].regexes[0] != rules.Rules[0].Match.compiledRegexes[0] {
		t.Fatal("NewClassifier() did not reuse the loader-compiled regex")
	}
	if udpRules[0].cidrs[0] != rules.Rules[1].Match.compiledCIDRs[0] {
		t.Fatal("NewClassifier() did not reuse the loader-parsed CIDR")
	}
}

func TestNewClassifierRejectsInvalidConstruction(t *testing.T) {
	catalog, rules := loadClassifierModels(
		t,
		validCatalogYAML,
		ruleYAML(
			"example_rule",
			"1",
			"example_service",
			"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
		),
	)
	tests := []struct {
		name    string
		catalog *Catalog
		rules   *Rules
		wantErr string
	}{
		{name: "nil catalog", rules: rules, wantErr: "catalog is required"},
		{name: "nil rules", catalog: catalog, wantErr: "rules are required"},
		{name: "unvalidated catalog", catalog: &Catalog{}, rules: rules, wantErr: "catalog was not produced"},
		{name: "unvalidated rules", catalog: catalog, rules: &Rules{}, wantErr: "rules were not produced"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClassifier(tt.catalog, tt.rules); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewClassifier() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestClassifierDNSExact(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	tests := []struct {
		name string
		dns  string
		want bool
	}{
		{name: "canonical", dns: "api.example.com", want: true},
		{name: "mixed case observed", dns: "API.Example.COM", want: true},
		{name: "surrounding whitespace", dns: "  api.example.com  ", want: true},
		{name: "trailing dot", dns: "api.example.com.", want: true},
		{name: "nonmatch", dns: "other.example.com"},
		{name: "empty DNS", dns: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifier, Endpoint{DNS: tt.dns, Protocol: "tcp", DstPort: 443})
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
}

func TestClassifierDNSSuffixUsesLabelBoundary(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_suffix: [tnsi.eu.com]\n      protocol: tcp\n      ports: [443]",
	)
	tests := []struct {
		name string
		dns  string
		want bool
	}{
		{name: "apex", dns: "tnsi.eu.com", want: true},
		{name: "one child", dns: "api.tnsi.eu.com", want: true},
		{name: "deeper child", dns: "deep.api.tnsi.eu.com", want: true},
		{name: "left substring is not label", dns: "eviltnsi.eu.com"},
		{name: "right extension is not child", dns: "tnsi.eu.com.example.org"},
		{name: "empty DNS", dns: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifier, Endpoint{DNS: tt.dns, Protocol: "tcp", DstPort: 443})
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
}

func TestClassifierDNSContains(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_contains: [ocpp]\n      protocol: tcp\n      ports: [443]",
	)
	tests := []struct {
		name string
		dns  string
		want bool
	}{
		{name: "literal substring", dns: "gw-ocpp.example.com", want: true},
		{name: "nocpp contains ocpp", dns: "nocpp.example.com", want: true},
		{name: "canonical lowercase observed", dns: "GW-OCPP.EXAMPLE.COM", want: true},
		{name: "nonmatch", dns: "gateway.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifier, Endpoint{DNS: tt.dns, Protocol: "tcp", DstPort: 443})
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
}

func TestClassifierDNSRegexIsFullCanonicalHostname(t *testing.T) {
	catalog, rules := loadClassifierModels(
		t,
		validCatalogYAML,
		ruleYAML(
			"example_rule",
			"1",
			"example_service",
			"dns_regex: ['api\\.example\\.com']\n      protocol: tcp\n      ports: [443]",
		),
	)
	source := rules.Rules[0].Match.DNSRegex[0]
	classifier, err := NewClassifier(catalog, rules)
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}
	tests := []struct {
		name string
		dns  string
		want bool
	}{
		{name: "full hostname", dns: "api.example.com", want: true},
		{name: "canonical lowercase observed", dns: "API.EXAMPLE.COM", want: true},
		{name: "prefix substring", dns: "xapi.example.com"},
		{name: "suffix substring", dns: "api.example.com.example.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifier, Endpoint{DNS: tt.dns, Protocol: "tcp", DstPort: 443})
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
	if got := rules.Rules[0].Match.DNSRegex[0]; got != source {
		t.Fatalf("regex source changed from %q to %q", source, got)
	}
}

func TestClassifierIPv4CIDR(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		endpoint Endpoint
		want     bool
	}{
		{
			name:     "host prefix",
			selector: "dst_ip_cidrs: [192.0.2.17/32]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DstIP: "192.0.2.17", Protocol: "tcp", DstPort: 443},
			want:     true,
		},
		{
			name:     "range lower boundary",
			selector: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DstIP: "192.0.2.0", Protocol: "tcp", DstPort: 443},
			want:     true,
		},
		{
			name:     "range upper boundary",
			selector: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DstIP: "192.0.2.255", Protocol: "tcp", DstPort: 443},
			want:     true,
		},
		{
			name:     "outside range",
			selector: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DstIP: "192.0.3.0", Protocol: "tcp", DstPort: 443},
		},
		{
			name:     "DNS does not disable IP match",
			selector: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DNS: "api.example.com", DstIP: "192.0.2.17", Protocol: "tcp", DstPort: 443},
			want:     true,
		},
		{
			name:     "IPv6 does not match IPv4 CIDR",
			selector: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DstIP: "2001:db8::1", Protocol: "tcp", DstPort: 443},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifierForMatch(t, tt.selector), tt.endpoint)
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
}

func TestClassifierProtocolAndPortPolicies(t *testing.T) {
	tests := []struct {
		name     string
		match    string
		endpoint Endpoint
		want     bool
	}{
		{
			name:     "TCP",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 443},
			want:     true,
		},
		{
			name:     "UDP",
			match:    "dns_exact: [api.example.com]\n      protocol: udp\n      ports: [53]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "udp", DstPort: 53},
			want:     true,
		},
		{
			name:     "protocol canonicalization",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: " TCP ", DstPort: 443},
			want:     true,
		},
		{
			name:     "protocol mismatch",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "udp", DstPort: 443},
		},
		{
			name:     "configured port",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443, 8443]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 8443},
			want:     true,
		},
		{
			name:     "port mismatch",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 8443},
		},
		{
			name:     "any port",
			match:    "dns_exact: [api.example.com]\n      protocol: tcp\n      any_port: true",
			endpoint: Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 65535},
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifierForMatch(t, tt.match), tt.endpoint)
			if got.Matched != tt.want {
				t.Fatalf("Matched = %v, want %v", got.Matched, tt.want)
			}
		})
	}
}

func TestClassifierEndpointValidation(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	tests := []struct {
		name      string
		endpoint  Endpoint
		wantField string
	}{
		{
			name:      "empty protocol",
			endpoint:  Endpoint{DNS: "api.example.com", DstPort: 443},
			wantField: "protocol",
		},
		{
			name:      "unsupported protocol",
			endpoint:  Endpoint{DNS: "api.example.com", Protocol: "sctp", DstPort: 443},
			wantField: "protocol",
		},
		{
			name:      "zero port",
			endpoint:  Endpoint{DNS: "api.example.com", Protocol: "tcp"},
			wantField: "dst_port",
		},
		{
			name:      "malformed non-empty IP",
			endpoint:  Endpoint{DNS: "api.example.com", DstIP: "not-an-ip", Protocol: "tcp", DstPort: 443},
			wantField: "dst_ip",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.Classify(context.Background(), []Endpoint{tt.endpoint})
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatalf("Result = %#v, want zero Result", result)
			}
			var validationErr *EndpointValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %v, want EndpointValidationError", err)
			}
			if validationErr.EndpointIndex != 0 || validationErr.Field != tt.wantField {
				t.Fatalf("EndpointValidationError = %#v", validationErr)
			}
		})
	}
}

func TestClassifierAllowsDNSOnlyAndIPv6DNSMatch(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	tests := []struct {
		name  string
		dstIP string
	}{
		{name: "empty destination IP"},
		{name: "valid IPv6 destination IP", dstIP: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOne(t, classifier, Endpoint{
				DNS:      "api.example.com",
				DstIP:    tt.dstIP,
				Protocol: "tcp",
				DstPort:  443,
			})
			if !got.Matched {
				t.Fatal("DNS selector did not match")
			}
		})
	}
}

func TestClassifierPriorityOnlyPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		catalogYAML string
		rulesYAML   string
		wantRule    string
		wantService string
	}{
		{
			name:        "lower number wins same service",
			catalogYAML: validCatalogYAML,
			rulesYAML: ruleYAML("worse_rule", "200", "example_service", exactMatch("api.example.com")) +
				ruleBody("better_rule", "100", "example_service", suffixMatch("example.com")),
			wantRule:    "better_rule",
			wantService: "example_service",
		},
		{
			name:        "lower number wins different service",
			catalogYAML: twoServiceCatalogYAML,
			rulesYAML: ruleYAML("worse_rule", "200", "service_one", exactMatch("api.example.com")) +
				ruleBody("better_rule", "100", "service_two", suffixMatch("example.com")),
			wantRule:    "better_rule",
			wantService: "service_two",
		},
		{
			name:        "exact 100 beats suffix 500",
			catalogYAML: validCatalogYAML,
			rulesYAML: ruleYAML("suffix_rule", "500", "example_service", suffixMatch("example.com")) +
				ruleBody("exact_rule", "100", "example_service", exactMatch("api.example.com")),
			wantRule:    "exact_rule",
			wantService: "example_service",
		},
		{
			name:        "suffix 500 beats contains 800",
			catalogYAML: validCatalogYAML,
			rulesYAML: ruleYAML("contains_rule", "800", "example_service", containsMatch("api")) +
				ruleBody("suffix_rule", "500", "example_service", suffixMatch("example.com")),
			wantRule:    "suffix_rule",
			wantService: "example_service",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := loadTestClassifier(t, tt.catalogYAML, tt.rulesYAML)
			result := classifyOne(t, classifier, Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 443})
			if !result.Matched ||
				result.Decision.MatchedRuleID != tt.wantRule ||
				result.Decision.LogicalServiceID != tt.wantService {
				t.Fatalf("classification = %#v", result)
			}
		})
	}
}

func TestClassifierSourceOrderDoesNotAffectDecision(t *testing.T) {
	first := ruleYAML("worse_rule", "200", "example_service", exactMatch("api.example.com")) +
		ruleBody("better_rule", "100", "example_service", suffixMatch("example.com"))
	second := ruleYAML("better_rule", "100", "example_service", suffixMatch("example.com")) +
		ruleBody("worse_rule", "200", "example_service", exactMatch("api.example.com"))
	endpoint := Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}

	left := classifyOne(t, loadTestClassifier(t, validCatalogYAML, first), endpoint)
	right := classifyOne(t, loadTestClassifier(t, validCatalogYAML, second), endpoint)
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("permuted classifications differ: %#v != %#v", left, right)
	}
}

func TestClassifierConflictDetails(t *testing.T) {
	rulesYAML := ruleYAML("z_exact", "100", "service_one", exactMatch("api.example.com")) +
		ruleBody("a_suffix", "100", "service_two", suffixMatch("example.com")) +
		ruleBody("m_contains", "100", "service_one", containsMatch("api")) +
		ruleBody("worse_rule", "500", "service_two", exactMatch("api.example.com"))
	classifier := loadTestClassifier(t, twoServiceCatalogYAML, rulesYAML)
	endpoint := Endpoint{
		SubjectID: "opaque-subject",
		DNS:       " API.Example.COM. ",
		DstIP:     "192.0.2.17",
		Protocol:  " TCP ",
		DstPort:   443,
	}

	result, err := classifier.Classify(context.Background(), []Endpoint{endpoint})
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("Result = %#v, want zero Result", result)
	}
	var conflictErr *ConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	want := Conflict{
		EndpointIndex: 0,
		SubjectID:     endpoint.SubjectID,
		DNS:           endpoint.DNS,
		DstIP:         endpoint.DstIP,
		Protocol:      "tcp",
		DstPort:       443,
		Priority:      100,
		Matches: []ConflictMatch{
			{RuleID: "a_suffix", LogicalServiceID: "service_two"},
			{RuleID: "m_contains", LogicalServiceID: "service_one"},
			{RuleID: "z_exact", LogicalServiceID: "service_one"},
		},
	}
	if !reflect.DeepEqual(conflictErr.Conflicts, []Conflict{want}) {
		t.Fatalf("Conflicts = %#v, want %#v", conflictErr.Conflicts, []Conflict{want})
	}
}

func TestClassifierConflictsSameServiceAndDifferentService(t *testing.T) {
	tests := []struct {
		name        string
		catalogYAML string
		second      string
	}{
		{name: "same service", catalogYAML: validCatalogYAML, second: "example_service"},
		{name: "different service", catalogYAML: twoServiceCatalogYAML, second: "service_two"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firstService := "example_service"
			if tt.second == "service_two" {
				firstService = "service_one"
			}
			rulesYAML := ruleYAML("exact_rule", "100", firstService, exactMatch("api.example.com")) +
				ruleBody("suffix_rule", "100", tt.second, suffixMatch("example.com"))
			_, err := loadTestClassifier(t, tt.catalogYAML, rulesYAML).Classify(
				context.Background(),
				[]Endpoint{{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}},
			)
			var conflictErr *ConflictError
			if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 1 {
				t.Fatalf("error = %#v, want one ConflictError", err)
			}
		})
	}
}

func TestClassifierMatcherTypeDoesNotResolveTie(t *testing.T) {
	rulesYAML := ruleYAML("exact_rule", "100", "example_service", exactMatch("api.example.com")) +
		ruleBody("suffix_rule", "100", "example_service", suffixMatch("example.com"))
	_, err := loadTestClassifier(t, validCatalogYAML, rulesYAML).Classify(
		context.Background(),
		[]Endpoint{{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}},
	)
	var conflictErr *ConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
}

func TestClassifierConflictOrderIsDeterministic(t *testing.T) {
	bodies := []string{
		ruleBody("z_exact", "100", "service_one", exactMatch("api.example.com")),
		ruleBody("a_suffix", "100", "service_two", suffixMatch("example.com")),
		ruleBody("m_contains", "100", "service_one", containsMatch("api")),
	}
	leftRules := "schema_version: 1\nrules:\n" + strings.Join(bodies, "")
	rightRules := "schema_version: 1\nrules:\n" + bodies[2] + bodies[0] + bodies[1]
	endpoint := Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}

	var got []*ConflictError
	for _, rulesYAML := range []string{leftRules, rightRules} {
		_, err := loadTestClassifier(t, twoServiceCatalogYAML, rulesYAML).Classify(
			context.Background(),
			[]Endpoint{endpoint},
		)
		var conflictErr *ConflictError
		if !errors.As(err, &conflictErr) {
			t.Fatalf("error = %v, want ConflictError", err)
		}
		got = append(got, conflictErr)
	}
	if !reflect.DeepEqual(got[0].Conflicts, got[1].Conflicts) {
		t.Fatalf("permuted conflicts differ: %#v != %#v", got[0].Conflicts, got[1].Conflicts)
	}
}

func TestClassifierAggregatesAllEndpointConflicts(t *testing.T) {
	rulesYAML := ruleYAML("exact_rule", "100", "example_service", exactMatch("api.example.com")) +
		ruleBody("suffix_rule", "100", "example_service", suffixMatch("example.com"))
	classifier := loadTestClassifier(t, validCatalogYAML, rulesYAML)
	endpoints := []Endpoint{
		{SubjectID: "first", DNS: "api.example.com", Protocol: "tcp", DstPort: 443},
		{SubjectID: "unmatched", DNS: "other.invalid", Protocol: "tcp", DstPort: 443},
		{SubjectID: "second", DNS: "api.example.com", Protocol: "tcp", DstPort: 443},
	}

	result, err := classifier.Classify(context.Background(), endpoints)
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("Result = %#v, want zero Result", result)
	}
	var conflictErr *ConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	if got := []int{conflictErr.Conflicts[0].EndpointIndex, conflictErr.Conflicts[1].EndpointIndex}; !reflect.DeepEqual(got, []int{0, 2}) {
		t.Fatalf("conflict endpoint order = %v", got)
	}
}

func TestConflictErrorStringIsBoundedButDetailsAreComplete(t *testing.T) {
	conflicts := make([]Conflict, 5)
	for i := range conflicts {
		conflicts[i] = Conflict{
			EndpointIndex: i,
			SubjectID:     strings.Repeat("subject", 50),
			Priority:      1,
			Matches: []ConflictMatch{
				{RuleID: "a"},
				{RuleID: "b"},
				{RuleID: "c"},
				{RuleID: "d"},
			},
		}
	}
	err := (&ConflictError{Conflicts: conflicts}).Error()
	if !strings.Contains(err, "... +2 endpoint(s)") || !strings.Contains(err, "... +1") {
		t.Fatalf("bounded error = %q", err)
	}
	if len(err) > 2_000 {
		t.Fatalf("error summary is not bounded: %d bytes", len(err))
	}
	if len(conflicts) != 5 || len(conflicts[0].Matches) != 4 {
		t.Fatal("structured conflicts were truncated")
	}
}

func TestClassifierBatchOrderAndInputImmutability(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	endpoints := []Endpoint{
		{SubjectID: "matched", DNS: " API.Example.COM. ", Protocol: " TCP ", DstPort: 443},
		{SubjectID: "unmatched", DNS: "other.example.com", Protocol: "tcp", DstPort: 443},
		{SubjectID: "matched-again", DNS: "api.example.com", Protocol: "tcp", DstPort: 443},
	}
	original := append([]Endpoint(nil), endpoints...)

	result, err := classifier.Classify(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if !reflect.DeepEqual(endpoints, original) {
		t.Fatalf("Classify() mutated inputs: %#v != %#v", endpoints, original)
	}
	if got := []bool{result.Entries[0].Matched, result.Entries[1].Matched, result.Entries[2].Matched}; !reflect.DeepEqual(got, []bool{true, false, true}) {
		t.Fatalf("match order = %v", got)
	}
	if result.Entries[0].Decision.MatchedRuleID != "example_rule" ||
		result.Entries[2].Decision.MatchedRuleID != "example_rule" ||
		result.Entries[1].Decision != (Decision{}) {
		t.Fatalf("decisions = %#v", result.Entries)
	}
}

func TestClassifierEmptyBatch(t *testing.T) {
	result, err := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	).Classify(context.Background(), nil)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("Entries = %#v, want empty", result.Entries)
	}
}

func TestClassifierCancellationReturnsNoPartialResult(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	endpoints := make([]Endpoint, 100)
	for i := range endpoints {
		endpoints[i] = Endpoint{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}
	}
	ctx := newCancelAfterErrChecksContext(25)

	result, err := classifier.Classify(ctx, endpoints)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Classify() error = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("Result = %#v, want zero Result", result)
	}
}

func TestClassifierAlreadyCancelledContext(t *testing.T) {
	classifier := classifierForMatch(
		t,
		"dns_exact: [api.example.com]\n      protocol: tcp\n      ports: [443]",
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := classifier.Classify(ctx, []Endpoint{{DNS: "api.example.com", Protocol: "tcp", DstPort: 443}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Classify() error = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("Result = %#v, want zero Result", result)
	}
}

func TestClassifierValidatesWholeBatchBeforeMatching(t *testing.T) {
	rulesYAML := ruleYAML("exact_rule", "100", "example_service", exactMatch("api.example.com")) +
		ruleBody("suffix_rule", "100", "example_service", suffixMatch("example.com"))
	classifier := loadTestClassifier(t, validCatalogYAML, rulesYAML)
	endpoints := []Endpoint{
		{DNS: "api.example.com", Protocol: "tcp", DstPort: 443},
		{DNS: "other.example.com", Protocol: "sctp", DstPort: 443},
	}

	result, err := classifier.Classify(context.Background(), endpoints)
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("Result = %#v, want zero Result", result)
	}
	var validationErr *EndpointValidationError
	if !errors.As(err, &validationErr) || validationErr.EndpointIndex != 1 {
		t.Fatalf("error = %#v, want validation error at endpoint 1", err)
	}
	var conflictErr *ConflictError
	if errors.As(err, &conflictErr) {
		t.Fatalf("matching ran before batch validation: %#v", conflictErr)
	}
}

func classifierForMatch(t *testing.T, match string) *Classifier {
	t.Helper()
	return loadTestClassifier(t, validCatalogYAML, ruleYAML("example_rule", "1", "example_service", match))
}

func loadTestClassifier(t *testing.T, catalogYAML, rulesYAML string) *Classifier {
	t.Helper()
	catalog, rules := loadClassifierModels(t, catalogYAML, rulesYAML)
	classifier, err := NewClassifier(catalog, rules)
	if err != nil {
		t.Fatalf("NewClassifier() error = %v", err)
	}
	return classifier
}

func loadClassifierModels(t *testing.T, catalogYAML, rulesYAML string) (*Catalog, *Rules) {
	t.Helper()
	catalog, err := LoadCatalog(writeTestFile(t, "classifier-catalog.yaml", catalogYAML))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	rules, err := LoadRules(writeTestFile(t, "classifier-rules.yaml", rulesYAML), catalog)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	return catalog, rules
}

func classifyOne(t *testing.T, classifier *Classifier, endpoint Endpoint) EndpointResult {
	t.Helper()
	result, err := classifier.Classify(context.Background(), []Endpoint{endpoint})
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(result.Entries))
	}
	return result.Entries[0]
}

func compiledRuleIDs(rules []compiledRule) []string {
	ids := make([]string, len(rules))
	for i := range rules {
		ids[i] = rules[i].id
	}
	return ids
}

func exactMatch(dns string) string {
	return "dns_exact: [" + dns + "]\n      protocol: tcp\n      ports: [443]"
}

func suffixMatch(dns string) string {
	return "dns_suffix: [" + dns + "]\n      protocol: tcp\n      ports: [443]"
}

func containsMatch(dns string) string {
	return "dns_contains: [" + dns + "]\n      protocol: tcp\n      ports: [443]"
}

type cancelAfterErrChecksContext struct {
	mu        sync.Mutex
	checks    int
	cancelAt  int
	done      chan struct{}
	cancelled bool
}

func newCancelAfterErrChecksContext(cancelAt int) *cancelAfterErrChecksContext {
	return &cancelAfterErrChecksContext{
		cancelAt: cancelAt,
		done:     make(chan struct{}),
	}
}

func (c *cancelAfterErrChecksContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (c *cancelAfterErrChecksContext) Done() <-chan struct{} {
	return c.done
}

func (c *cancelAfterErrChecksContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	if !c.cancelled && c.checks >= c.cancelAt {
		close(c.done)
		c.cancelled = true
	}
	if c.cancelled {
		return context.Canceled
	}
	return nil
}

func (c *cancelAfterErrChecksContext) Value(any) any {
	return nil
}
