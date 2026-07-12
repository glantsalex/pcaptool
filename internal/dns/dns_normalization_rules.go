// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DNSNormalizationRules is the minimal rule set supported by
// --dns-normalization-rules. It intentionally supports only dns_normalize rules.
type DNSNormalizationRules struct {
	rules []DNSNormalizeRule
}

type dnsNormalizationRulesFile struct {
	Rules []DNSNormalizeRule `yaml:"rules"`
}

// DNSNormalizeRule rewrites selected direct DNS evidence to one normalized DNS
// name before topology donation and final artifact writing.
type DNSNormalizeRule struct {
	RuleID string                `yaml:"rule_id"`
	Type   string                `yaml:"type"`
	NetID  string                `yaml:"net_id"`
	Match  DNSNormalizeRuleMatch `yaml:"match"`
	Set    DNSNormalizeRuleSet   `yaml:"set"`
}

type DNSNormalizeRuleMatch struct {
	Protocol      string   `yaml:"protocol"`
	Ports         []uint16 `yaml:"ports"`
	ObservedDNS   []string `yaml:"observed_dns"`
	CNAMEContains []string `yaml:"cname_contains"`
}

type DNSNormalizeRuleSet struct {
	NormalizedDNS string `yaml:"normalized_dns"`
}

// DNSNormalizationAudit records one topology row changed by a dns_normalize
// rule.
type DNSNormalizationAudit struct {
	NetID            string
	RuleID           string
	IssuerIP         string
	DestinationIP    string
	Protocol         string
	Port             uint16
	ObservedDNS      string
	NormalizedDNS    string
	OriginalSource   string
	NormalizedSource string
	CNAMERequired    bool
	CNAMEMatched     bool
	CNAMEChain       []string
}

// LoadDNSNormalizationRules loads and validates DNS normalization rules from a
// YAML file. YAML order is preserved and the first matching rule wins.
func LoadDNSNormalizationRules(path string) (*DNSNormalizationRules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DNS normalization rules %q: %w", path, err)
	}
	var file dnsNormalizationRulesFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse DNS normalization rules %q: %w", path, err)
	}
	rules := &DNSNormalizationRules{rules: append([]DNSNormalizeRule(nil), file.Rules...)}
	if err := rules.validate(); err != nil {
		return nil, fmt.Errorf("validate DNS normalization rules %q: %w", path, err)
	}
	return rules, nil
}

func (r *DNSNormalizationRules) validate() error {
	if r == nil {
		return nil
	}
	seenIDs := make(map[string]struct{}, len(r.rules))
	for i := range r.rules {
		rule := &r.rules[i]
		rule.RuleID = strings.TrimSpace(rule.RuleID)
		rule.Type = strings.TrimSpace(rule.Type)
		rule.NetID = strings.TrimSpace(rule.NetID)
		rule.Match.Protocol = strings.ToLower(strings.TrimSpace(rule.Match.Protocol))
		rule.Set.NormalizedDNS = canonicalDNSName(rule.Set.NormalizedDNS)

		if rule.RuleID == "" {
			return fmt.Errorf("rule %d: rule_id is required", i+1)
		}
		if _, ok := seenIDs[rule.RuleID]; ok {
			return fmt.Errorf("rule %q: duplicate rule_id", rule.RuleID)
		}
		seenIDs[rule.RuleID] = struct{}{}
		if rule.Type != "dns_normalize" {
			return fmt.Errorf("rule %q: unsupported type %q", rule.RuleID, rule.Type)
		}
		if rule.NetID == "" {
			return fmt.Errorf("rule %q: net_id is required", rule.RuleID)
		}
		if rule.Match.Protocol == "" {
			return fmt.Errorf("rule %q: match.protocol is required", rule.RuleID)
		}
		if len(rule.Match.Ports) == 0 {
			return fmt.Errorf("rule %q: match.ports is required", rule.RuleID)
		}
		for _, port := range rule.Match.Ports {
			if port == 0 {
				return fmt.Errorf("rule %q: match.ports contains invalid port 0", rule.RuleID)
			}
		}
		if len(rule.Match.ObservedDNS) == 0 {
			return fmt.Errorf("rule %q: match.observed_dns is required", rule.RuleID)
		}
		for j, name := range rule.Match.ObservedDNS {
			name = canonicalDNSName(name)
			if name == "" {
				return fmt.Errorf("rule %q: match.observed_dns[%d] is empty", rule.RuleID, j)
			}
			rule.Match.ObservedDNS[j] = name
		}
		for j, name := range rule.Match.CNAMEContains {
			name = canonicalDNSName(name)
			if name == "" {
				return fmt.Errorf("rule %q: match.cname_contains[%d] is empty", rule.RuleID, j)
			}
			rule.Match.CNAMEContains[j] = name
		}
		if rule.Set.NormalizedDNS == "" {
			return fmt.Errorf("rule %q: set.normalized_dns is required", rule.RuleID)
		}
	}
	return nil
}

// ApplyDNSNormalization applies dns_normalize rules to direct dns+synack rows.
// It returns a fresh slice plus audit rows for entries that changed.
func ApplyDNSNormalization(netID string, entries []TopologyEntry, rules *DNSNormalizationRules) ([]TopologyEntry, []DNSNormalizationAudit) {
	if len(entries) == 0 || rules == nil || len(rules.rules) == 0 {
		return entries, nil
	}

	out := append([]TopologyEntry(nil), entries...)
	audit := make([]DNSNormalizationAudit, 0)
	for i := range out {
		row := &out[i]
		if strings.ToLower(strings.TrimSpace(row.DNSSource)) != "dns+synack" {
			continue
		}
		observed := canonicalDNSName(row.DNSName)
		if observed == "" {
			continue
		}
		for _, rule := range rules.rules {
			match, cnameMatched := rule.matches(netID, *row, observed)
			if !match {
				continue
			}
			originalSource := row.DNSSource
			row.ObservedDNSName = observed
			row.NormalizedDNSName = rule.Set.NormalizedDNS
			row.NormalizationRuleID = rule.RuleID
			row.DNSName = rule.Set.NormalizedDNS
			row.DNSSource = "dns+synack+norm"
			audit = append(audit, DNSNormalizationAudit{
				NetID:            strings.TrimSpace(netID),
				RuleID:           rule.RuleID,
				IssuerIP:         row.IssuerIP,
				DestinationIP:    row.DestinationIP,
				Protocol:         row.Protocol,
				Port:             row.Port,
				ObservedDNS:      observed,
				NormalizedDNS:    rule.Set.NormalizedDNS,
				OriginalSource:   originalSource,
				NormalizedSource: row.DNSSource,
				CNAMERequired:    len(rule.Match.CNAMEContains) > 0,
				CNAMEMatched:     cnameMatched,
				CNAMEChain:       splitTopologyCNAMEChain(row.CNAMEChain),
			})
			break
		}
	}
	return out, audit
}

func (r DNSNormalizeRule) matches(netID string, row TopologyEntry, observed string) (bool, bool) {
	if strings.TrimSpace(netID) != r.NetID {
		return false, false
	}
	if strings.ToLower(strings.TrimSpace(row.Protocol)) != r.Match.Protocol {
		return false, false
	}
	portOK := false
	for _, port := range r.Match.Ports {
		if row.Port == port {
			portOK = true
			break
		}
	}
	if !portOK {
		return false, false
	}
	observedOK := false
	for _, pattern := range r.Match.ObservedDNS {
		if dnsNameMatchesPattern(observed, pattern) {
			observedOK = true
			break
		}
	}
	if !observedOK {
		return false, false
	}
	if len(r.Match.CNAMEContains) == 0 {
		return true, false
	}
	for _, cname := range splitTopologyCNAMEChain(row.CNAMEChain) {
		cname = canonicalDNSName(cname)
		for _, wanted := range r.Match.CNAMEContains {
			if cname == wanted || strings.Contains(cname, wanted) || dnsNameMatchesPattern(cname, wanted) {
				return true, true
			}
		}
	}
	return false, false
}

func dnsNameMatchesPattern(name string, pattern string) bool {
	name = canonicalDNSName(name)
	pattern = canonicalDNSName(pattern)
	if name == "" || pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return name == pattern
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// WriteDNSNormalizationAuditCSV writes normalization audit rows. Callers should
// only create the artifact when at least one normalization occurred.
func WriteDNSNormalizationAuditCSV(w io.Writer, records []DNSNormalizationAudit) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{
		"net_id",
		"rule_id",
		"issuer_ip",
		"destination_ip",
		"protocol",
		"port",
		"observed_dns",
		"normalized_dns",
		"original_source",
		"normalized_source",
		"cname_required",
		"cname_matched",
		"cname_chain",
	}); err != nil {
		return err
	}
	for _, record := range sortedDNSNormalizationAudit(records) {
		if err := writer.Write([]string{
			record.NetID,
			record.RuleID,
			record.IssuerIP,
			record.DestinationIP,
			record.Protocol,
			strconv.FormatUint(uint64(record.Port), 10),
			record.ObservedDNS,
			record.NormalizedDNS,
			record.OriginalSource,
			record.NormalizedSource,
			strconv.FormatBool(record.CNAMERequired),
			strconv.FormatBool(record.CNAMEMatched),
			strings.Join(record.CNAMEChain, ";"),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func sortedDNSNormalizationAudit(records []DNSNormalizationAudit) []DNSNormalizationAudit {
	out := append([]DNSNormalizationAudit(nil), records...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.NetID != b.NetID {
			return a.NetID < b.NetID
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.IssuerIP != b.IssuerIP {
			return a.IssuerIP < b.IssuerIP
		}
		if a.DestinationIP != b.DestinationIP {
			return a.DestinationIP < b.DestinationIP
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.ObservedDNS < b.ObservedDNS
	})
	return out
}
