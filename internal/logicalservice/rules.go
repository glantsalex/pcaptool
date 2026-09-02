// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"fmt"
	"net/netip"
	"regexp"
)

// Rules is a validated logical-service rule file.
type Rules struct {
	SchemaVersion uint32 `yaml:"schema_version"`
	Rules         []Rule `yaml:"rules"`

	validated bool
}

// Rule maps one endpoint selector, protocol, and port policy to a service ID.
// Priority zero and equal priorities are valid configuration. Lower numeric
// priority wins during classification. More than one matching rule at the
// lowest matching priority is a fatal classification conflict, whether those
// rules reference the same service or different services. File order and
// matcher type do not resolve ties; priority is the only precedence mechanism.
type Rule struct {
	ID        string     `yaml:"id"`
	Priority  *uint32    `yaml:"priority"`
	ServiceID string     `yaml:"service_id"`
	Match     *RuleMatch `yaml:"match"`
}

// RuleMatch defines one endpoint selector plus a protocol and port policy.
// Selector and port fields are lists only; scalar-or-list YAML is unsupported.
type RuleMatch struct {
	DNSExact    []string `yaml:"dns_exact"`
	DNSSuffix   []string `yaml:"dns_suffix"`
	DNSRegex    []string `yaml:"dns_regex"`
	DNSContains []string `yaml:"dns_contains"`
	DstIPCIDRs  []string `yaml:"dst_ip_cidrs"`

	Protocol string   `yaml:"protocol"`
	Ports    []uint16 `yaml:"ports"`
	AnyPort  *bool    `yaml:"any_port"`

	compiledRegexes []*regexp.Regexp
	compiledCIDRs   []netip.Prefix
}

// LoadRules reads and strictly validates a logical-service rules YAML file
// against catalog. Regexes and IPv4 CIDRs are compiled once during loading.
func LoadRules(path string, catalog *Catalog) (*Rules, error) {
	if catalog == nil {
		return nil, fmt.Errorf("load logical-service rules %q: catalog is required", path)
	}
	var rules Rules
	if err := decodeYAMLFile(path, "logical-service rules", &rules); err != nil {
		return nil, err
	}
	if err := rules.validate(catalog); err != nil {
		return nil, fmt.Errorf("validate logical-service rules %q: %w", path, err)
	}
	return &rules, nil
}
