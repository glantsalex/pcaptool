// Copyright © 2025 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReverseResolver supplies reverse and forward DNS lookups. A nil resolver, or
// nil function fields, use net.DefaultResolver.
type ReverseResolver struct {
	LookupAddr func(context.Context, string) ([]string, error)
	LookupHost func(context.Context, string) ([]string, error)
}

// ReverseDNSLookupOptions controls bounded reverse-DNS completion.
type ReverseDNSLookupOptions struct {
	Workers  int
	Timeout  time.Duration
	Progress func(processed, total int)
}

// ReverseDNSLookupRecord is one deterministic diagnostic row per queried IP.
type ReverseDNSLookupRecord struct {
	IP               string
	Status           string
	RawPTR           string
	NormalizedName   string
	Source           string
	Reason           string
	ForwardConfirmed bool
	ForwardIPs       string
	Error            string
}

const defaultReverseDNSLookupTimeout = 2 * time.Second

var awsEC2PTRPattern = regexp.MustCompile(`^ec2-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)\.([a-z0-9-]+)\.compute\.amazonaws\.com$`)

var reverseDNSNamePlaceholders = map[string]struct{}{
	"":                     {},
	"[no-dns-attribution]": {},
	"no dns attribution":   {},
	"no attribution":       {},
	"none":                 {},
}

var reverseDNSSourcePlaceholders = map[string]struct{}{
	"":                   {},
	"mid-session":        {},
	"no dns attribution": {},
	"no attribution":     {},
	"none":               {},
}

type reverseDNSLookupResult struct {
	record ReverseDNSLookupRecord
	name   string
	source string
}

// CompleteTopologyWithReverseDNS performs last-resort PTR completion for
// otherwise-unattributed public IPv4 topology rows. It returns a completed copy
// and one IP-sorted diagnostic record per queried address. Individual DNS
// failures are recorded and are not operation-level errors.
func CompleteTopologyWithReverseDNS(
	ctx context.Context,
	entries []TopologyEntry,
	resolver *ReverseResolver,
	options ReverseDNSLookupOptions,
) ([]TopologyEntry, []ReverseDNSLookupRecord, error) {
	out := append([]TopologyEntry(nil), entries...)
	if err := ctx.Err(); err != nil {
		return out, nil, err
	}

	candidateSet := make(map[string]struct{})
	for _, entry := range out {
		ip, ok := reverseDNSCandidateIP(entry)
		if ok {
			candidateSet[ip] = struct{}{}
		}
	}
	candidates := make([]string, 0, len(candidateSet))
	for ip := range candidateSet {
		candidates = append(candidates, ip)
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return out, []ReverseDNSLookupRecord{}, nil
	}

	lookupAddr, lookupHost := reverseDNSLookupFunctions(resolver)
	workers := options.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers < 1 {
			workers = 1
		}
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultReverseDNSLookupTimeout
	}

	jobs := make(chan string)
	results := make(chan reverseDNSLookupResult)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-jobs:
					if !ok {
						return
					}
					result := lookupReverseDNSCandidate(ctx, ip, timeout, lookupAddr, lookupHost)
					results <- result
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	lookupResults := make([]reverseDNSLookupResult, 0, len(candidates))
	processed := 0
	for result := range results {
		lookupResults = append(lookupResults, result)
		processed++
		if options.Progress != nil {
			options.Progress(processed, len(candidates))
		}
	}
	sort.Slice(lookupResults, func(i, j int) bool {
		return lookupResults[i].record.IP < lookupResults[j].record.IP
	})

	selected := make(map[string]reverseDNSLookupResult, len(lookupResults))
	records := make([]ReverseDNSLookupRecord, 0, len(lookupResults))
	for _, result := range lookupResults {
		records = append(records, result.record)
		if result.name != "" {
			selected[result.record.IP] = result
		}
	}
	for i := range out {
		ip, ok := reverseDNSCandidateIP(out[i])
		if !ok {
			continue
		}
		result, ok := selected[ip]
		if !ok {
			continue
		}
		out[i].DNSName = result.name
		out[i].DNSSource = result.source
	}

	if err := ctx.Err(); err != nil {
		return out, records, err
	}
	return out, records, nil
}

func reverseDNSCandidateIP(entry TopologyEntry) (string, bool) {
	if _, ok := reverseDNSNamePlaceholders[strings.ToLower(strings.TrimSpace(entry.DNSName))]; !ok {
		return "", false
	}
	if _, ok := reverseDNSSourcePlaceholders[strings.ToLower(strings.TrimSpace(entry.DNSSource))]; !ok {
		return "", false
	}
	ip, ok := canonicalIPv4String(entry.DestinationIP)
	if !ok {
		return "", false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !isPublicIPv4(addr) {
		return "", false
	}
	return ip, true
}

func reverseDNSLookupFunctions(resolver *ReverseResolver) (
	func(context.Context, string) ([]string, error),
	func(context.Context, string) ([]string, error),
) {
	lookupAddr := net.DefaultResolver.LookupAddr
	lookupHost := net.DefaultResolver.LookupHost
	if resolver != nil {
		if resolver.LookupAddr != nil {
			lookupAddr = resolver.LookupAddr
		}
		if resolver.LookupHost != nil {
			lookupHost = resolver.LookupHost
		}
	}
	return lookupAddr, lookupHost
}

func lookupReverseDNSCandidate(
	parent context.Context,
	ip string,
	timeout time.Duration,
	lookupAddr func(context.Context, string) ([]string, error),
	lookupHost func(context.Context, string) ([]string, error),
) reverseDNSLookupResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	record := ReverseDNSLookupRecord{IP: ip}
	rawNames, err := lookupAddr(ctx, ip)
	if err != nil {
		record.Error = err.Error()
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			record.Status = "nxdomain"
			record.Reason = "nxdomain"
		} else {
			record.Status = "error"
			record.Reason = "lookup_error"
		}
		return reverseDNSLookupResult{record: record}
	}

	rawPTRs := canonicalSortedUniqueNames(rawNames)
	record.RawPTR = strings.Join(rawPTRs, ";")
	if len(rawNames) == 0 {
		record.Status = "no_ptr"
		record.Reason = "no_ptr"
		return reverseDNSLookupResult{record: record}
	}

	usableRaw := make([]string, 0, len(rawPTRs))
	normalized := make([]string, 0, len(rawPTRs))
	awsMismatch := false
	noisyIPEncoded := false
	for _, name := range rawPTRs {
		if normalizedName, aws, matches := normalizeAWSReverseDNSName(name, ip); aws {
			if matches {
				normalized = append(normalized, normalizedName)
			} else {
				awsMismatch = true
			}
			continue
		}
		if reverseDNSNameEncodesIPv4(name, ip) {
			noisyIPEncoded = true
			continue
		}
		if isUsableReverseDNSName(name) {
			usableRaw = append(usableRaw, name)
		}
	}
	normalized = sortedUniqueStrings(normalized)

	confirmed := make([]string, 0, len(usableRaw))
	forwardIPSet := make(map[string]struct{})
	forwardErrors := make([]string, 0)
	for _, name := range usableRaw {
		forwardIPs, forwardErr := lookupHost(ctx, name)
		if forwardErr != nil {
			forwardErrors = append(forwardErrors, name+": "+forwardErr.Error())
			continue
		}
		matched := false
		for _, rawIP := range forwardIPs {
			parsed := net.ParseIP(strings.TrimSpace(rawIP))
			if parsed == nil || parsed.To4() == nil {
				continue
			}
			canonical := parsed.To4().String()
			forwardIPSet[canonical] = struct{}{}
			if canonical == ip {
				matched = true
			}
		}
		if matched {
			confirmed = append(confirmed, name)
		}
	}
	record.ForwardIPs = strings.Join(sortedStringSet(forwardIPSet), ";")
	if len(forwardErrors) > 0 {
		record.Error = strings.Join(forwardErrors, "; ")
	}

	result := reverseDNSLookupResult{record: record}
	switch {
	case len(confirmed) == 1:
		result.name = confirmed[0]
		result.source = "ptr+fcrdns+matrix"
		result.record.Status = "used_fcrdns"
		result.record.NormalizedName = result.name
		result.record.Source = result.source
		result.record.Reason = "forward_confirmed"
		result.record.ForwardConfirmed = true
	case len(confirmed) > 1:
		result.record.Status = "ambiguous"
		result.record.Reason = "ambiguous_ptr"
		result.record.ForwardConfirmed = true
	case len(usableRaw) == 1:
		result.name = usableRaw[0]
		result.source = "ptr+matrix"
		result.record.Status = "used_raw"
		result.record.NormalizedName = result.name
		result.record.Source = result.source
		result.record.Reason = "valid_ptr"
	case len(usableRaw) > 1:
		result.record.Status = "ambiguous"
		result.record.Reason = "ambiguous_ptr"
	case len(normalized) == 1:
		result.name = normalized[0]
		result.source = "ptr-normalized+matrix"
		result.record.Status = "used_normalized"
		result.record.NormalizedName = result.name
		result.record.Source = result.source
		result.record.Reason = "aws_ec2_ip_encoded"
	case len(normalized) > 1:
		result.record.Status = "ambiguous"
		result.record.Reason = "ambiguous_ptr"
	default:
		result.record.Status = "skipped_noise"
		if awsMismatch {
			result.record.Reason = "aws_ec2_ip_mismatch"
		} else if noisyIPEncoded {
			result.record.Reason = "noisy_ip_encoded"
		} else {
			result.record.Reason = "invalid_name"
		}
	}
	return result
}

func canonicalSortedUniqueNames(names []string) []string {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = canonicalDNSName(name)
		if name != "" {
			set[name] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func sortedUniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isUsableReverseDNSName(name string) bool {
	if !IsResolvableDNSName(name) {
		return false
	}
	if name == "home.arpa" {
		return false
	}
	for _, suffix := range []string{".lan", ".localhost", ".home.arpa"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

func reverseDNSNameEncodesIPv4(name, queriedIP string) bool {
	octets := strings.Split(queriedIP, ".")
	if len(octets) != 4 {
		return false
	}
	labels := strings.Split(name, ".")
	if containsMatchingIPv4Octets(labels, octets) {
		return true
	}
	for _, label := range labels {
		if containsMatchingIPv4Octets(strings.Split(label, "-"), octets) {
			return true
		}
	}
	return false
}

func containsMatchingIPv4Octets(parts, want []string) bool {
	if len(parts) < 4 || len(want) != 4 {
		return false
	}
	for start := 0; start <= len(parts)-4; start++ {
		matches := true
		for i := 0; i < 4; i++ {
			if !numericOctetEqual(parts[start+i], want[i]) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func numericOctetEqual(got, want string) bool {
	if got == "" {
		return false
	}
	for _, r := range got {
		if r < '0' || r > '9' {
			return false
		}
	}
	gotValue, err := strconv.Atoi(got)
	if err != nil || gotValue < 0 || gotValue > 255 {
		return false
	}
	wantValue, err := strconv.Atoi(want)
	return err == nil && gotValue == wantValue
}

func normalizeAWSReverseDNSName(name, queriedIP string) (normalized string, aws, matches bool) {
	parts := awsEC2PTRPattern.FindStringSubmatch(name)
	if parts == nil {
		return "", false, false
	}
	encodedIP := strings.Join(parts[1:5], ".")
	canonical, ok := canonicalIPv4String(encodedIP)
	if !ok || canonical != queriedIP {
		return "", true, false
	}
	return "ec2." + parts[5] + ".compute.amazonaws.com", true, true
}

// WriteReverseDNSLookupCSV writes reverse-DNS diagnostics sorted by canonical
// IP. Multi-valued fields are expected to be semicolon-separated.
func WriteReverseDNSLookupCSV(w io.Writer, records []ReverseDNSLookupRecord) error {
	rows := append([]ReverseDNSLookupRecord(nil), records...)
	for i := range rows {
		if ip, ok := canonicalIPv4String(rows[i].IP); ok {
			rows[i].IP = ip
		}
		rows[i].RawPTR = strings.Join(canonicalSortedUniqueNames(strings.Split(rows[i].RawPTR, ";")), ";")
		forwardIPs := make(map[string]struct{})
		for _, rawIP := range strings.Split(rows[i].ForwardIPs, ";") {
			if ip, ok := canonicalIPv4String(rawIP); ok {
				forwardIPs[ip] = struct{}{}
			}
		}
		rows[i].ForwardIPs = strings.Join(sortedStringSet(forwardIPs), ";")
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })

	csvWriter := csv.NewWriter(w)
	if err := csvWriter.Write([]string{
		"ip", "status", "raw_ptr", "normalized_name", "source", "reason",
		"forward_confirmed", "forward_ips", "error",
	}); err != nil {
		return fmt.Errorf("write reverse DNS CSV header: %w", err)
	}
	for _, row := range rows {
		if err := csvWriter.Write([]string{
			row.IP,
			row.Status,
			row.RawPTR,
			row.NormalizedName,
			row.Source,
			row.Reason,
			strconv.FormatBool(row.ForwardConfirmed),
			row.ForwardIPs,
			row.Error,
		}); err != nil {
			return fmt.Errorf("write reverse DNS CSV row for %s: %w", row.IP, err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush reverse DNS CSV: %w", err)
	}
	return nil
}
