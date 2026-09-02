// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/aglants/pcaptool/internal/dnsname"
	"gopkg.in/yaml.v3"
)

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func decodeYAMLFile(path, kind string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s %q: %w", kind, path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse %s %q: %w", kind, path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return fmt.Errorf("parse %s %q: %w", kind, path, err)
		}
		return fmt.Errorf("parse %s %q: multiple YAML documents are not supported", kind, path)
	}
	return nil
}

func (c *Catalog) validate() error {
	c.validated = false
	if c.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version: unsupported value %d; use %d", c.SchemaVersion, schemaVersion)
	}
	if c.Services == nil {
		return fmt.Errorf("services: field is required")
	}
	if len(c.Services) == 0 {
		return fmt.Errorf("services: must contain at least one service")
	}
	c.serviceIDs = make(map[string]struct{}, len(c.Services))
	for i := range c.Services {
		service := &c.Services[i]
		service.ID = strings.TrimSpace(service.ID)
		service.Name = strings.TrimSpace(service.Name)
		context := fmt.Sprintf("service %d", i+1)
		if service.ID == "" {
			return fmt.Errorf("%s: id is required", context)
		}
		context = fmt.Sprintf("service %q", service.ID)
		if !identifierPattern.MatchString(service.ID) {
			return fmt.Errorf("%s: id value %q must match %s", context, service.ID, identifierPattern.String())
		}
		if _, exists := c.serviceIDs[service.ID]; exists {
			return fmt.Errorf("%s: duplicate id", context)
		}
		if service.Name == "" {
			return fmt.Errorf("%s: name is required", context)
		}
		c.serviceIDs[service.ID] = struct{}{}
	}
	c.validated = true
	return nil
}

func (r *Rules) validate(catalog *Catalog) error {
	r.validated = false
	if r.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version: unsupported value %d; use %d", r.SchemaVersion, schemaVersion)
	}
	if r.Rules == nil {
		return fmt.Errorf("rules: field is required")
	}
	if len(r.Rules) == 0 {
		return fmt.Errorf("rules: must contain at least one rule")
	}
	seenIDs := make(map[string]struct{}, len(r.Rules))
	for i := range r.Rules {
		rule := &r.Rules[i]
		rule.ID = strings.TrimSpace(rule.ID)
		rule.ServiceID = strings.TrimSpace(rule.ServiceID)
		context := fmt.Sprintf("rule %d", i+1)
		if rule.ID == "" {
			return fmt.Errorf("%s: id is required", context)
		}
		context = fmt.Sprintf("rule %q", rule.ID)
		if !identifierPattern.MatchString(rule.ID) {
			return fmt.Errorf("%s: id value %q must match %s", context, rule.ID, identifierPattern.String())
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("%s: duplicate id", context)
		}
		seenIDs[rule.ID] = struct{}{}
		if rule.Priority == nil {
			return fmt.Errorf("%s: priority is required", context)
		}
		if rule.ServiceID == "" {
			return fmt.Errorf("%s: service_id is required", context)
		}
		if _, exists := catalog.serviceIDs[rule.ServiceID]; !exists {
			return fmt.Errorf("%s: service_id value %q is not present in the catalog", context, rule.ServiceID)
		}
		if rule.Match == nil {
			return fmt.Errorf("%s: match block is required", context)
		}
		if err := validateMatch(rule.Match); err != nil {
			return fmt.Errorf("%s: %w", context, err)
		}
	}
	r.validated = true
	return nil
}

func validateMatch(match *RuleMatch) error {
	selectors := []struct {
		name   string
		values []string
	}{
		{name: "dns_exact", values: match.DNSExact},
		{name: "dns_suffix", values: match.DNSSuffix},
		{name: "dns_regex", values: match.DNSRegex},
		{name: "dns_contains", values: match.DNSContains},
		{name: "dst_ip_cidrs", values: match.DstIPCIDRs},
	}
	selected := 0
	for _, selector := range selectors {
		if selector.values != nil && len(selector.values) == 0 {
			return fmt.Errorf("match.%s: selector must not be empty", selector.name)
		}
		if len(selector.values) > 0 {
			selected++
		}
	}
	if selected == 0 {
		return fmt.Errorf("match: exactly one endpoint selector is required")
	}
	if selected > 1 {
		return fmt.Errorf("match: exactly one endpoint selector is allowed")
	}

	var err error
	switch {
	case len(match.DNSExact) > 0:
		match.DNSExact, err = validateCanonicalDNSValues("dns_exact", match.DNSExact, validateDNSExact)
	case len(match.DNSSuffix) > 0:
		match.DNSSuffix, err = validateCanonicalDNSValues("dns_suffix", match.DNSSuffix, validateDNSSuffix)
	case len(match.DNSContains) > 0:
		match.DNSContains, err = validateCanonicalDNSValues("dns_contains", match.DNSContains, validateDNSContains)
	case len(match.DNSRegex) > 0:
		match.DNSRegex, match.compiledRegexes, err = compileRegexes(match.DNSRegex)
	case len(match.DstIPCIDRs) > 0:
		match.DstIPCIDRs, match.compiledCIDRs, err = compileIPv4CIDRs(match.DstIPCIDRs)
	}
	if err != nil {
		return err
	}

	match.Protocol = strings.ToLower(strings.TrimSpace(match.Protocol))
	if match.Protocol != "tcp" && match.Protocol != "udp" {
		return fmt.Errorf("match.protocol: unsupported value %q; use tcp or udp", match.Protocol)
	}
	if match.Ports != nil && len(match.Ports) == 0 {
		return fmt.Errorf("match.ports: list must not be empty")
	}
	if match.AnyPort != nil && !*match.AnyPort {
		return fmt.Errorf("match.any_port: false is invalid; omit the field or set it to true")
	}
	hasPorts := len(match.Ports) > 0
	hasAnyPort := match.AnyPort != nil && *match.AnyPort
	if hasPorts && hasAnyPort {
		return fmt.Errorf("match: ports and any_port cannot both be set")
	}
	if !hasPorts && !hasAnyPort {
		return fmt.Errorf("match: exactly one port policy is required: non-empty ports or any_port: true")
	}
	seenPorts := make(map[uint16]struct{}, len(match.Ports))
	for _, port := range match.Ports {
		if port == 0 {
			return fmt.Errorf("match.ports: value 0 is outside the valid range 1-65535")
		}
		if _, exists := seenPorts[port]; exists {
			return fmt.Errorf("match.ports: duplicate value %d", port)
		}
		seenPorts[port] = struct{}{}
	}
	return nil
}

func validateCanonicalDNSValues(field string, values []string, validate func(string) error) ([]string, error) {
	canonical := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		value = dnsname.Normalize(value)
		if err := validate(value); err != nil {
			return nil, fmt.Errorf("match.%s value %q: %w", field, value, err)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("match.%s: duplicate canonical value %q", field, value)
		}
		seen[value] = struct{}{}
		canonical[i] = value
	}
	return canonical, nil
}

func validateDNSExact(value string) error {
	return validateDNSNameSelector(value)
}

func validateDNSSuffix(value string) error {
	return validateDNSNameSelector(value)
}

func validateDNSNameSelector(value string) error {
	if value == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.ContainsAny(value, "*?") {
		return fmt.Errorf("wildcard syntax is not supported")
	}
	if strings.HasPrefix(value, ".") {
		return fmt.Errorf("must not start with a dot")
	}
	if strings.HasSuffix(value, ".") {
		return fmt.Errorf("must not end with a dot")
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("must not contain empty DNS labels")
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("must not contain whitespace")
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func validateDNSContains(value string) error {
	if value == "" {
		return fmt.Errorf("must not be empty")
	}
	return nil
}

func compileRegexes(values []string) ([]string, []*regexp.Regexp, error) {
	sources := make([]string, len(values))
	compiled := make([]*regexp.Regexp, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, nil, fmt.Errorf("match.dns_regex: value must not be empty")
		}
		if _, exists := seen[value]; exists {
			return nil, nil, fmt.Errorf("match.dns_regex: duplicate expression %q", value)
		}
		re, err := regexp.Compile("^(?:" + value + ")$")
		if err != nil {
			return nil, nil, fmt.Errorf("match.dns_regex value %q: invalid RE2 expression: %w", value, err)
		}
		seen[value] = struct{}{}
		sources[i] = value
		compiled[i] = re
	}
	return sources, compiled, nil
}

func compileIPv4CIDRs(values []string) ([]string, []netip.Prefix, error) {
	sources := make([]string, len(values))
	compiled := make([]netip.Prefix, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, fmt.Errorf("match.dst_ip_cidrs value %q: invalid CIDR: %w", value, err)
		}
		addr := prefix.Addr()
		if addr.Is4In6() {
			return nil, nil, fmt.Errorf("match.dst_ip_cidrs value %q: IPv4-mapped IPv6 CIDRs are not supported", value)
		}
		if !addr.Is4() {
			return nil, nil, fmt.Errorf("match.dst_ip_cidrs value %q: IPv6 CIDRs are not supported by logical-service schema version 1", value)
		}
		masked := prefix.Masked()
		if prefix != masked {
			return nil, nil, fmt.Errorf("match.dst_ip_cidrs value %q has host bits set; use %q", value, masked.String())
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, nil, fmt.Errorf("match.dst_ip_cidrs: duplicate canonical prefix %q", canonical)
		}
		seen[canonical] = struct{}{}
		sources[i] = canonical
		compiled[i] = prefix
	}
	return sources, compiled, nil
}
