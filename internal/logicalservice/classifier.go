// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aglants/pcaptool/internal/dnsname"
)

const (
	maxConflictsInError = 3
	maxMatchesInError   = 3
	maxErrorValueRunes  = 64
)

// Endpoint is one observed network endpoint to classify. DstIP may be empty
// for DNS-only observations. SubjectID is opaque and is preserved verbatim.
type Endpoint struct {
	SubjectID string
	DNS       string
	DstIP     string
	Protocol  string
	DstPort   uint16
}

// Decision identifies the single rule and logical service selected for a
// matched endpoint.
type Decision struct {
	LogicalServiceID string
	MatchedRuleID    string
}

// EndpointResult contains one endpoint's classification state. Its position
// corresponds to the endpoint at the same input index. Decision is the zero
// value when Matched is false.
type EndpointResult struct {
	Matched  bool
	Decision Decision
}

// Result contains endpoint results in the same order as the input batch.
type Result struct {
	Entries []EndpointResult
}

// EndpointValidationError reports one invalid endpoint field.
type EndpointValidationError struct {
	EndpointIndex int
	Field         string
	Value         string
	Reason        string
}

// Error implements error.
func (e *EndpointValidationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"logical-service endpoint %d field %s value %q: %s",
		e.EndpointIndex,
		e.Field,
		e.Value,
		e.Reason,
	)
}

// ConflictMatch identifies one rule participating in a classification
// conflict.
type ConflictMatch struct {
	RuleID           string
	LogicalServiceID string
}

// Conflict describes all rules tied at the lowest matching priority for one
// endpoint. DNS and DstIP preserve the original observed values.
type Conflict struct {
	EndpointIndex int
	SubjectID     string
	DNS           string
	DstIP         string
	Protocol      string
	DstPort       uint16
	Priority      uint32
	Matches       []ConflictMatch
}

// ConflictError aggregates every classification conflict in an input batch.
// Conflicts contains complete structured details; Error intentionally renders
// only a bounded summary.
type ConflictError struct {
	Conflicts []Conflict
}

// Error implements error.
func (e *ConflictError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "logical-service classification conflicts: %d endpoint(s)", len(e.Conflicts))
	limit := min(len(e.Conflicts), maxConflictsInError)
	for i := 0; i < limit; i++ {
		conflict := e.Conflicts[i]
		fmt.Fprintf(
			&b,
			"; endpoint %d subject %s priority %d rules [",
			conflict.EndpointIndex,
			boundedQuotedErrorValue(conflict.SubjectID),
			conflict.Priority,
		)
		matchLimit := min(len(conflict.Matches), maxMatchesInError)
		for j := 0; j < matchLimit; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(boundedQuotedErrorValue(conflict.Matches[j].RuleID))
		}
		if len(conflict.Matches) > matchLimit {
			fmt.Fprintf(&b, ", ... +%d", len(conflict.Matches)-matchLimit)
		}
		b.WriteByte(']')
	}
	if len(e.Conflicts) > limit {
		fmt.Fprintf(&b, "; ... +%d endpoint(s)", len(e.Conflicts)-limit)
	}
	return b.String()
}

func boundedQuotedErrorValue(value string) string {
	runes := []rune(value)
	if len(runes) > maxErrorValueRunes {
		value = string(runes[:maxErrorValueRunes]) + "…"
	}
	return strconv.QuoteToASCII(value)
}

type selectorKind uint8

const (
	selectorDNSExact selectorKind = iota + 1
	selectorDNSSuffix
	selectorDNSContains
	selectorDNSRegex
	selectorDstIPCIDR
)

type compiledRule struct {
	id           string
	serviceID    string
	priority     uint32
	kind         selectorKind
	exact        map[string]struct{}
	alternatives []string
	regexes      []*regexp.Regexp
	cidrs        []netip.Prefix
	anyPort      bool
	ports        map[uint16]struct{}
}

// Classifier is an immutable logical-service classifier. A Classifier is safe
// for concurrent use after construction.
type Classifier struct {
	rulesByProtocol map[string][]compiledRule
}

// NewClassifier snapshots loader-validated catalog and rules models into an
// immutable classifier. It does not mutate either input model.
func NewClassifier(catalog *Catalog, rules *Rules) (*Classifier, error) {
	if catalog == nil {
		return nil, fmt.Errorf("new logical-service classifier: catalog is required")
	}
	if rules == nil {
		return nil, fmt.Errorf("new logical-service classifier: rules are required")
	}
	if !catalog.validated {
		return nil, fmt.Errorf("new logical-service classifier: catalog was not produced by successful validation")
	}
	if !rules.validated {
		return nil, fmt.Errorf("new logical-service classifier: rules were not produced by successful validation")
	}

	serviceIDs := make(map[string]struct{}, len(catalog.Services))
	for _, service := range catalog.Services {
		serviceIDs[service.ID] = struct{}{}
	}

	byProtocol := map[string][]compiledRule{
		"tcp": nil,
		"udp": nil,
	}
	for i := range rules.Rules {
		source := &rules.Rules[i]
		if source.Priority == nil || source.Match == nil {
			return nil, fmt.Errorf("new logical-service classifier: validated rule %d has incomplete state", i)
		}
		_, ok := serviceIDs[source.ServiceID]
		if !ok {
			return nil, fmt.Errorf(
				"new logical-service classifier: validated rule %q references unknown service %q",
				source.ID,
				source.ServiceID,
			)
		}
		compiled, err := compileClassifierRule(source)
		if err != nil {
			return nil, fmt.Errorf("new logical-service classifier: rule %q: %w", source.ID, err)
		}
		protocol := source.Match.Protocol
		if protocol != "tcp" && protocol != "udp" {
			return nil, fmt.Errorf("new logical-service classifier: validated rule %q has unsupported protocol %q", source.ID, protocol)
		}
		byProtocol[protocol] = append(byProtocol[protocol], compiled)
	}

	for protocol := range byProtocol {
		sort.Slice(byProtocol[protocol], func(i, j int) bool {
			left := byProtocol[protocol][i]
			right := byProtocol[protocol][j]
			if left.priority != right.priority {
				return left.priority < right.priority
			}
			return left.id < right.id
		})
	}

	return &Classifier{rulesByProtocol: byProtocol}, nil
}

func compileClassifierRule(source *Rule) (compiledRule, error) {
	match := source.Match
	compiled := compiledRule{
		id:        source.ID,
		serviceID: source.ServiceID,
		priority:  *source.Priority,
		anyPort:   match.AnyPort != nil && *match.AnyPort,
	}
	if !compiled.anyPort {
		compiled.ports = make(map[uint16]struct{}, len(match.Ports))
		for _, port := range match.Ports {
			compiled.ports[port] = struct{}{}
		}
	}

	switch {
	case len(match.DNSExact) > 0:
		compiled.kind = selectorDNSExact
		compiled.exact = make(map[string]struct{}, len(match.DNSExact))
		for _, value := range match.DNSExact {
			compiled.exact[value] = struct{}{}
		}
	case len(match.DNSSuffix) > 0:
		compiled.kind = selectorDNSSuffix
		compiled.alternatives = append([]string(nil), match.DNSSuffix...)
	case len(match.DNSContains) > 0:
		compiled.kind = selectorDNSContains
		compiled.alternatives = append([]string(nil), match.DNSContains...)
	case len(match.DNSRegex) > 0:
		if len(match.compiledRegexes) != len(match.DNSRegex) {
			return compiledRule{}, fmt.Errorf("compiled regex state is incomplete")
		}
		compiled.kind = selectorDNSRegex
		compiled.regexes = append([]*regexp.Regexp(nil), match.compiledRegexes...)
	case len(match.DstIPCIDRs) > 0:
		if len(match.compiledCIDRs) != len(match.DstIPCIDRs) {
			return compiledRule{}, fmt.Errorf("compiled CIDR state is incomplete")
		}
		compiled.kind = selectorDstIPCIDR
		compiled.cidrs = append([]netip.Prefix(nil), match.compiledCIDRs...)
	default:
		return compiledRule{}, fmt.Errorf("endpoint selector is missing")
	}

	return compiled, nil
}

type preparedEndpoint struct {
	original Endpoint
	dns      string
	ip       netip.Addr
	hasIP    bool
	protocol string
}

// Classify validates and classifies a batch of endpoints. Input and output
// order are preserved. Any validation error, context error, or classification
// conflict returns the zero Result; conflicts are aggregated across the batch.
func (c *Classifier) Classify(ctx context.Context, endpoints []Endpoint) (Result, error) {
	if c == nil {
		return Result{}, fmt.Errorf("logical-service classifier is nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	prepared := make([]preparedEndpoint, len(endpoints))
	for i, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		canonical, err := prepareEndpoint(i, endpoint)
		if err != nil {
			return Result{}, err
		}
		prepared[i] = canonical
	}

	entries := make([]EndpointResult, len(prepared))
	conflicts := make([]Conflict, 0)
	for i := range prepared {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		entry, conflict, err := c.classifyEndpoint(ctx, i, prepared[i])
		if err != nil {
			return Result{}, err
		}
		entries[i] = entry
		if conflict != nil {
			conflicts = append(conflicts, *conflict)
		}
	}
	if len(conflicts) > 0 {
		return Result{}, &ConflictError{Conflicts: conflicts}
	}
	return Result{Entries: entries}, nil
}

func prepareEndpoint(index int, endpoint Endpoint) (preparedEndpoint, error) {
	prepared := preparedEndpoint{
		original: endpoint,
		dns:      dnsname.Normalize(endpoint.DNS),
		protocol: strings.ToLower(strings.TrimSpace(endpoint.Protocol)),
	}
	if prepared.protocol == "" {
		return preparedEndpoint{}, &EndpointValidationError{
			EndpointIndex: index,
			Field:         "protocol",
			Value:         endpoint.Protocol,
			Reason:        "must not be empty",
		}
	}
	if prepared.protocol != "tcp" && prepared.protocol != "udp" {
		return preparedEndpoint{}, &EndpointValidationError{
			EndpointIndex: index,
			Field:         "protocol",
			Value:         endpoint.Protocol,
			Reason:        "must be tcp or udp",
		}
	}
	if endpoint.DstPort == 0 {
		return preparedEndpoint{}, &EndpointValidationError{
			EndpointIndex: index,
			Field:         "dst_port",
			Value:         strconv.FormatUint(uint64(endpoint.DstPort), 10),
			Reason:        "must be in the range 1-65535",
		}
	}
	dstIP := strings.TrimSpace(endpoint.DstIP)
	if dstIP != "" {
		addr, err := netip.ParseAddr(dstIP)
		if err != nil {
			return preparedEndpoint{}, &EndpointValidationError{
				EndpointIndex: index,
				Field:         "dst_ip",
				Value:         endpoint.DstIP,
				Reason:        "must be empty or a valid IP address",
			}
		}
		prepared.ip = addr
		prepared.hasIP = true
	}
	return prepared, nil
}

func (c *Classifier) classifyEndpoint(
	ctx context.Context,
	index int,
	endpoint preparedEndpoint,
) (EndpointResult, *Conflict, error) {
	entry := EndpointResult{}
	rules := c.rulesByProtocol[endpoint.protocol]
	var (
		winningPriority uint32
		winners         []compiledRule
		haveWinner      bool
	)
	for i := range rules {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return EndpointResult{}, nil, err
			}
		}
		rule := rules[i]
		if haveWinner && rule.priority > winningPriority {
			break
		}
		if !rule.matches(endpoint) {
			continue
		}
		if !haveWinner {
			winningPriority = rule.priority
			haveWinner = true
		}
		winners = append(winners, rule)
	}
	if !haveWinner {
		return entry, nil, nil
	}
	if len(winners) == 1 {
		winner := winners[0]
		entry.Matched = true
		entry.Decision = Decision{
			LogicalServiceID: winner.serviceID,
			MatchedRuleID:    winner.id,
		}
		return entry, nil, nil
	}

	matches := make([]ConflictMatch, len(winners))
	for i := range winners {
		matches[i] = ConflictMatch{
			RuleID:           winners[i].id,
			LogicalServiceID: winners[i].serviceID,
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].RuleID != matches[j].RuleID {
			return matches[i].RuleID < matches[j].RuleID
		}
		return matches[i].LogicalServiceID < matches[j].LogicalServiceID
	})
	return entry, &Conflict{
		EndpointIndex: index,
		SubjectID:     endpoint.original.SubjectID,
		DNS:           endpoint.original.DNS,
		DstIP:         endpoint.original.DstIP,
		Protocol:      endpoint.protocol,
		DstPort:       endpoint.original.DstPort,
		Priority:      winningPriority,
		Matches:       matches,
	}, nil
}

func (r compiledRule) matches(endpoint preparedEndpoint) bool {
	if !r.anyPort {
		if _, ok := r.ports[endpoint.original.DstPort]; !ok {
			return false
		}
	}
	switch r.kind {
	case selectorDNSExact:
		if endpoint.dns == "" {
			return false
		}
		_, ok := r.exact[endpoint.dns]
		return ok
	case selectorDNSSuffix:
		if endpoint.dns == "" {
			return false
		}
		for _, suffix := range r.alternatives {
			if endpoint.dns == suffix || strings.HasSuffix(endpoint.dns, "."+suffix) {
				return true
			}
		}
	case selectorDNSContains:
		if endpoint.dns == "" {
			return false
		}
		for _, value := range r.alternatives {
			if strings.Contains(endpoint.dns, value) {
				return true
			}
		}
	case selectorDNSRegex:
		if endpoint.dns == "" {
			return false
		}
		for _, re := range r.regexes {
			if re.MatchString(endpoint.dns) {
				return true
			}
		}
	case selectorDstIPCIDR:
		if !endpoint.hasIP || !endpoint.ip.Is4() {
			return false
		}
		for _, prefix := range r.cidrs {
			if prefix.Contains(endpoint.ip) {
				return true
			}
		}
	}
	return false
}
