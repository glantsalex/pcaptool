// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"path/filepath"
	"testing"
)

func TestLoadRulesValidSelectorsAndPolicies(t *testing.T) {
	tests := []struct {
		name  string
		match string
	}{
		{name: "dns exact", match: "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [443]"},
		{name: "dns suffix any port", match: "dns_suffix: [example.invalid]\n      protocol: TCP\n      any_port: true"},
		{name: "dns contains", match: "dns_contains: [gateway]\n      protocol: udp\n      ports: [53]"},
		{name: "dns regex", match: "dns_regex: ['[a-z]+\\.example\\.invalid']\n      protocol: tcp\n      ports: [443]"},
		{name: "IPv4 CIDR", match: "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443, 8443]"},
		{name: "IPv4 host prefix", match: "dst_ip_cidrs: [203.0.113.17/32]\n      protocol: tcp\n      ports: [443]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := loadRulesYAML(t, ruleYAML("example_rule", "0", "example_service", tt.match))
			if len(rules.Rules) != 1 || rules.Rules[0].Priority == nil || *rules.Rules[0].Priority != 0 {
				t.Fatalf("LoadRules() = %#v", rules)
			}
			if rules.Rules[0].Match.Protocol != "tcp" && rules.Rules[0].Match.Protocol != "udp" {
				t.Fatalf("protocol not canonicalized: %q", rules.Rules[0].Match.Protocol)
			}
		})
	}
}

func TestLoadRulesValidation(t *testing.T) {
	validMatch := "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [443]"
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "unsupported schema", yaml: "schema_version: 2\nrules: []\n", wantErr: "unsupported value 2"},
		{name: "missing rules", yaml: "schema_version: 1\n", wantErr: "rules: field is required"},
		{name: "empty rules", yaml: "schema_version: 1\nrules: []\n", wantErr: "must contain at least one rule"},
		{name: "missing rule id", yaml: ruleYAML("", "1", "example_service", validMatch), wantErr: "id is required"},
		{name: "duplicate rule id", yaml: ruleYAML("example_rule", "1", "example_service", validMatch) + ruleBody(" example_rule ", "2", "example_service", validMatch), wantErr: "duplicate id"},
		{name: "invalid rule id", yaml: ruleYAML("Example-Rule", "1", "example_service", validMatch), wantErr: "must match"},
		{name: "missing priority", yaml: ruleYAML("example_rule", "", "example_service", validMatch), wantErr: "priority is required"},
		{name: "negative priority", yaml: ruleYAML("example_rule", "-1", "example_service", validMatch), wantErr: "cannot unmarshal"},
		{name: "missing service id", yaml: ruleYAML("example_rule", "1", "", validMatch), wantErr: "service_id is required"},
		{name: "unknown service", yaml: ruleYAML("example_rule", "1", "missing_service", validMatch), wantErr: "not present in the catalog"},
		{name: "missing match", yaml: ruleYAML("example_rule", "1", "example_service", ""), wantErr: "match block is required"},
		{name: "missing selector", yaml: ruleYAML("example_rule", "1", "example_service", "protocol: tcp\n      ports: [443]"), wantErr: "exactly one endpoint selector is required"},
		{name: "multiple selectors", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      dns_suffix: [example.invalid]\n      protocol: tcp\n      ports: [443]"), wantErr: "exactly one endpoint selector is allowed"},
		{name: "empty selector", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: []\n      protocol: tcp\n      ports: [443]"), wantErr: "selector must not be empty"},
		{name: "unknown field", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protcol: tcp\n      ports: [443]"), wantErr: "field protcol not found"},
		{name: "unsupported protocol", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: icmp\n      ports: [443]"), wantErr: "use tcp or udp"},
		{name: "missing port policy", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp"), wantErr: "exactly one port policy"},
		{name: "ports plus any port", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [443]\n      any_port: true"), wantErr: "cannot both be set"},
		{name: "any port false", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      any_port: false"), wantErr: "false is invalid"},
		{name: "empty ports", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: []"), wantErr: "list must not be empty"},
		{name: "zero port", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [0]"), wantErr: "valid range 1-65535"},
		{name: "overflow port", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [65536]"), wantErr: "cannot unmarshal"},
		{name: "negative port", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [-1]"), wantErr: "cannot unmarshal"},
		{name: "duplicate port", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [443, 443]"), wantErr: "duplicate value 443"},
		{name: "invalid regex", yaml: ruleYAML("example_rule", "1", "example_service", "dns_regex: ['[unterminated']\n      protocol: tcp\n      ports: [443]"), wantErr: "invalid RE2 expression"},
		{name: "unsupported regex", yaml: ruleYAML("example_rule", "1", "example_service", "dns_regex: ['foo(?=bar)']\n      protocol: tcp\n      ports: [443]"), wantErr: "invalid RE2 expression"},
		{name: "duplicate regex", yaml: ruleYAML("example_rule", "1", "example_service", "dns_regex: ['foo', ' foo ']\n      protocol: tcp\n      ports: [443]"), wantErr: "duplicate expression"},
		{name: "invalid CIDR", yaml: ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: [not-a-prefix]\n      protocol: tcp\n      ports: [443]"), wantErr: "invalid CIDR"},
		{name: "host bits", yaml: ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: [203.0.113.17/24]\n      protocol: tcp\n      ports: [443]"), wantErr: "use \"203.0.113.0/24\""},
		{name: "duplicate CIDR", yaml: ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: [192.0.2.0/24, ' 192.0.2.0/24 ']\n      protocol: tcp\n      ports: [443]"), wantErr: "duplicate canonical prefix"},
		{name: "IPv6", yaml: ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: ['2001:db8::/32']\n      protocol: tcp\n      ports: [443]"), wantErr: "IPv6 CIDRs are not supported by logical-service schema version 1"},
		{name: "mapped IPv6", yaml: ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: ['::ffff:192.0.2.0/120']\n      protocol: tcp\n      ports: [443]"), wantErr: "IPv4-mapped IPv6 CIDRs are not supported"},
		{name: "scalar selector", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: api.example.invalid\n      protocol: tcp\n      ports: [443]"), wantErr: "cannot unmarshal"},
		{name: "scalar ports", yaml: ruleYAML("example_rule", "1", "example_service", "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: 443"), wantErr: "cannot unmarshal"},
		{name: "multiple documents", yaml: ruleYAML("example_rule", "1", "example_service", validMatch) + "---\nschema_version: 1\nrules: []\n", wantErr: "multiple YAML documents"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog := loadCatalogYAML(t, validCatalogYAML)
			path := writeTestFile(t, "rules.yaml", tt.yaml)
			_, err := LoadRules(path, catalog)
			assertErrorContains(t, err, path, tt.wantErr)
		})
	}
}

func TestLoadRulesDNSExactAccepted(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "qualified name", value: "api.example.com", want: "api.example.com"},
		{name: "hyphenated internal name", value: "internal-host", want: "internal-host"},
		{name: "service discovery name", value: "_service._tcp.internal", want: "_service._tcp.internal"},
		{name: "underscore internal name", value: "my_backend.internal", want: "my_backend.internal"},
		{name: "mixed case", value: "API.Example.COM", want: "api.example.com"},
		{name: "single trailing dot", value: "api.example.com.", want: "api.example.com"},
		{name: "surrounding whitespace", value: "  API.Example.COM.  ", want: "api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := "dns_exact: ['" + tt.value + "']"
			rules := loadRulesYAML(t, ruleYAML("example_rule", "1", "example_service", selector+"\n      protocol: tcp\n      ports: [443]"))
			got := rules.Rules[0].Match.DNSExact[0]
			if got != tt.want {
				t.Fatalf("canonical selector = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRulesDNSExactRejected(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		wantErr  string
	}{
		{name: "empty value", selector: "dns_exact: ['   ']", wantErr: "must not be empty"},
		{name: "leading dot", selector: "dns_exact: ['.api.example.com']", wantErr: "must not start with a dot"},
		{name: "consecutive dots", selector: "dns_exact: ['api..example.com']", wantErr: "empty DNS labels"},
		{name: "residual trailing dot", selector: "dns_exact: ['api.example.com..']", wantErr: "must not end with a dot"},
		{name: "embedded ASCII space", selector: "dns_exact: ['api example.com']", wantErr: "must not contain whitespace"},
		{name: "embedded tab", selector: "dns_exact: [\"api\\texample.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded newline", selector: "dns_exact: [\"api\\nexample.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded Unicode whitespace", selector: "dns_exact: [\"api\\u2003example.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded control", selector: "dns_exact: [\"api\\x01example.com\"]", wantErr: "must not contain control characters"},
		{name: "wildcard", selector: "dns_exact: ['*.example.com']", wantErr: "wildcard syntax is not supported"},
		{name: "duplicate after canonicalization", selector: "dns_exact: [' API.EXAMPLE.COM. ', api.example.com]", wantErr: "duplicate canonical value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.selector + "\n      protocol: tcp\n      ports: [443]"
			catalog := loadCatalogYAML(t, validCatalogYAML)
			path := writeTestFile(t, "rules.yaml", ruleYAML("example_rule", "1", "example_service", match))
			_, err := LoadRules(path, catalog)
			assertErrorContains(t, err, path, tt.wantErr)
		})
	}
}

func TestLoadRulesDNSSuffixAccepted(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "qualified name", value: "example.com", want: "example.com"},
		{name: "single-label internal name", value: "internal", want: "internal"},
		{name: "service discovery name", value: "_service._tcp.internal", want: "_service._tcp.internal"},
		{name: "underscore internal name", value: "my_backend.internal", want: "my_backend.internal"},
		{name: "mixed case", value: "Example.COM", want: "example.com"},
		{name: "single trailing dot", value: "example.com.", want: "example.com"},
		{name: "surrounding whitespace", value: "  Example.COM.  ", want: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := "dns_suffix: ['" + tt.value + "']"
			rules := loadRulesYAML(t, ruleYAML("example_rule", "1", "example_service", selector+"\n      protocol: tcp\n      ports: [443]"))
			got := rules.Rules[0].Match.DNSSuffix[0]
			if got != tt.want {
				t.Fatalf("canonical selector = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRulesDNSSuffixRejected(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		wantErr  string
	}{
		{name: "empty value", selector: "dns_suffix: ['.']", wantErr: "must not be empty"},
		{name: "leading dot", selector: "dns_suffix: ['.example.com']", wantErr: "must not start with a dot"},
		{name: "consecutive dots", selector: "dns_suffix: ['example..com']", wantErr: "empty DNS labels"},
		{name: "residual trailing dot", selector: "dns_suffix: ['example.com..']", wantErr: "must not end with a dot"},
		{name: "embedded ASCII space", selector: "dns_suffix: ['example .com']", wantErr: "must not contain whitespace"},
		{name: "embedded tab", selector: "dns_suffix: [\"example\\t.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded newline", selector: "dns_suffix: [\"example\\n.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded Unicode whitespace", selector: "dns_suffix: [\"example\\u2003.com\"]", wantErr: "must not contain whitespace"},
		{name: "embedded control", selector: "dns_suffix: [\"example\\x01.com\"]", wantErr: "must not contain control characters"},
		{name: "wildcard", selector: "dns_suffix: ['*.example.com']", wantErr: "wildcard syntax is not supported"},
		{name: "duplicate after canonicalization", selector: "dns_suffix: [' Example.COM. ', example.com]", wantErr: "duplicate canonical value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.selector + "\n      protocol: tcp\n      ports: [443]"
			catalog := loadCatalogYAML(t, validCatalogYAML)
			path := writeTestFile(t, "rules.yaml", ruleYAML("example_rule", "1", "example_service", match))
			_, err := LoadRules(path, catalog)
			assertErrorContains(t, err, path, tt.wantErr)
		})
	}
}

func TestLoadRulesDNSContainsValidationAndCanonicalization(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		want     string
		wantErr  string
	}{
		{name: "canonicalized", selector: "dns_contains: [' OCPP. ']", want: "ocpp"},
		{name: "empty value", selector: "dns_contains: ['   ']", wantErr: "must not be empty"},
		{name: "duplicate after canonicalization", selector: "dns_contains: ['OCPP', 'ocpp.']", wantErr: "duplicate canonical value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.selector + "\n      protocol: tcp\n      ports: [443]"
			catalog := loadCatalogYAML(t, validCatalogYAML)
			path := writeTestFile(t, "rules.yaml", ruleYAML("example_rule", "1", "example_service", match))
			rules, err := LoadRules(path, catalog)
			if tt.wantErr != "" {
				assertErrorContains(t, err, path, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("LoadRules() error = %v", err)
			}
			if got := rules.Rules[0].Match.DNSContains[0]; got != tt.want {
				t.Fatalf("canonical selector = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRulesAllowsEqualPriorities(t *testing.T) {
	match := "dns_exact: [api.example.invalid]\n      protocol: tcp\n      ports: [443]"
	yaml := ruleYAML("first_rule", "0", "example_service", match) +
		ruleBody("second_rule", "0", "example_service", match)

	rules := loadRulesYAML(t, yaml)
	if len(rules.Rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules.Rules))
	}
	for i, rule := range rules.Rules {
		if rule.Priority == nil || *rule.Priority != 0 {
			t.Fatalf("rule %d priority = %v, want 0", i, rule.Priority)
		}
	}
}

func TestLoadRulesCompilesRegexWithoutRewritingSource(t *testing.T) {
	rules := loadRulesYAML(t, ruleYAML("example_rule", "1", "example_service", "dns_regex: ['  API\\.Example\\.Invalid  ']\n      protocol: tcp\n      ports: [443]"))
	match := rules.Rules[0].Match
	if got := match.DNSRegex[0]; got != `API\.Example\.Invalid` {
		t.Fatalf("regex source = %q", got)
	}
	if len(match.compiledRegexes) != 1 {
		t.Fatalf("compiled regex count = %d, want 1", len(match.compiledRegexes))
	}
	if !match.compiledRegexes[0].MatchString("API.Example.Invalid") || match.compiledRegexes[0].MatchString("xAPI.Example.Invalid") {
		t.Fatal("compiled regex does not use unchanged, implicit full-hostname semantics")
	}
}

func TestLoadRulesCompilesIPv4CIDRsOnce(t *testing.T) {
	rules := loadRulesYAML(t, ruleYAML("example_rule", "1", "example_service", "dst_ip_cidrs: [192.0.2.0/24]\n      protocol: tcp\n      ports: [443]"))
	match := rules.Rules[0].Match
	if len(match.compiledCIDRs) != 1 || match.compiledCIDRs[0].String() != "192.0.2.0/24" {
		t.Fatalf("compiled CIDRs = %#v", match.compiledCIDRs)
	}
}

func TestExampleConfigurationFiles(t *testing.T) {
	root := filepath.Join("..", "..", "configs")
	catalog, err := LoadCatalog(filepath.Join(root, "logical-services.example.yaml"))
	if err != nil {
		t.Fatalf("load example catalog: %v", err)
	}
	if _, err := LoadRules(filepath.Join(root, "logical-service-rules.example.yaml"), catalog); err != nil {
		t.Fatalf("load example rules: %v", err)
	}
}

func loadCatalogYAML(t *testing.T, contents string) *Catalog {
	t.Helper()
	catalog, err := LoadCatalog(writeTestFile(t, "catalog.yaml", contents))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	return catalog
}

func loadRulesYAML(t *testing.T, contents string) *Rules {
	t.Helper()
	catalog := loadCatalogYAML(t, validCatalogYAML)
	rules, err := LoadRules(writeTestFile(t, "rules.yaml", contents), catalog)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	return rules
}

func ruleYAML(id, priority, serviceID, match string) string {
	return "schema_version: 1\nrules:\n" + ruleBody(id, priority, serviceID, match)
}

func ruleBody(id, priority, serviceID, match string) string {
	out := "  - id: " + id + "\n"
	if priority != "" {
		out += "    priority: " + priority + "\n"
	}
	if serviceID != "" {
		out += "    service_id: " + serviceID + "\n"
	}
	if match != "" {
		out += "    match:\n      " + match + "\n"
	}
	return out
}
