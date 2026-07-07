// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aglants/pcaptool/progress"
)

// ResolveUnresolvedOptions controls concurrency/timeouts.
type ResolveUnresolvedOptions struct {
	Workers int
	Timeout time.Duration
	Servers []string
}

// IPv4LookupFunc resolves one DNS name. Implementations must honor ctx. Callers
// may inject a deterministic implementation for tests; a nil function uses the
// configured UDP resolvers.
type IPv4LookupFunc func(context.Context, string) ([]net.IP, error)

// DNSNameIPv4Resolution is one canonical DNS name and its sorted, unique IPv4
// results from active resolution.
type DNSNameIPv4Resolution struct {
	DNSName string
	IPv4s   []string
}

// ActiveResolveAuditRecord describes one canonical name offered to active
// resolution and how its result related to the topology matrix.
type ActiveResolveAuditRecord struct {
	DNSName             string
	Status              string
	IPv4s               []string
	MatrixIPs           []string
	MatrixRowsCompleted int
	Error               string
}

// makeResolver creates a net.Resolver that uses the given DNS servers (UDP/53)
// in a round-robin manner.
func makeResolver(servers []string, timeout time.Duration) *net.Resolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8"}
	}

	dialer := &net.Dialer{Timeout: timeout}
	var rr uint32

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			i := int(atomic.AddUint32(&rr, 1)-1) % len(servers)
			server := servers[i]
			// Force UDP/53 – this matches your current design.
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// DefaultResolveUnresolvedOptions returns sane defaults tuned for speed.
func DefaultResolveUnresolvedOptions() ResolveUnresolvedOptions {
	return ResolveUnresolvedOptions{
		Workers: min(max(runtime.GOMAXPROCS(0)*8, 32), 256),
		Timeout: 10 * time.Second,
		Servers: []string{"8.8.8.8", "1.1.1.1"},
	}
}

// IsResolvableDNSName returns true if name looks like a real FQDN worth resolving.
func IsResolvableDNSName(name string) bool {
	s := strings.TrimSpace(strings.TrimSuffix(name, "."))
	if s == "" {
		return false
	}
	ls := strings.ToLower(s)

	// Explicit rejects
	if ls == "localhost" {
		return false
	}
	if ls == "in-addr.arpa" || ls == "ip6.arpa" {
		return false
	}
	for _, suffix := range []string{".local", ".loc", ".internal", ".eth0", ".in-addr.arpa", ".ip6.arpa"} {
		if strings.HasSuffix(ls, suffix) {
			return false
		}
	}

	// Must contain at least one dot (FQDN-ish)
	if !strings.Contains(ls, ".") {
		return false
	}

	// Reject underscores and spaces (your example HYC_...)
	if strings.ContainsAny(ls, " _\t\r\n") {
		return false
	}

	// Basic sanity: only allow letters/digits/dot/dash
	for _, r := range ls {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}

	// Reject absurd sizes
	if len(ls) > 253 {
		return false
	}

	// Labels must be 1..63, not start/end with '-'
	parts := strings.Split(ls, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 63 {
			return false
		}
		if strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
			return false
		}
	}

	return true
}

// ResolveDNSNamesIPv4 actively resolves a finite set of DNS names without
// mutating DNS transactions. Work is bounded by the candidate count, a maximum
// of 32 workers, and the per-name timeout. Individual lookup failures are
// omitted; parent-context cancellation aborts the operation.
func ResolveDNSNamesIPv4(
	ctx context.Context,
	names []string,
	opt ResolveUnresolvedOptions,
	lookup IPv4LookupFunc,
) ([]DNSNameIPv4Resolution, error) {
	resolutions, _, err := ResolveDNSNamesIPv4WithAudit(ctx, names, opt, lookup)
	return resolutions, err
}

// ResolveDNSNamesIPv4WithAudit resolves names exactly like
// ResolveDNSNamesIPv4 while retaining deterministic per-name outcomes.
func ResolveDNSNamesIPv4WithAudit(
	ctx context.Context,
	names []string,
	opt ResolveUnresolvedOptions,
	lookup IPv4LookupFunc,
) ([]DNSNameIPv4Resolution, []ActiveResolveAuditRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	def := DefaultResolveUnresolvedOptions()
	if opt.Workers <= 0 {
		opt.Workers = def.Workers
	}
	if opt.Timeout <= 0 {
		opt.Timeout = def.Timeout
	}
	if len(opt.Servers) == 0 {
		opt.Servers = append([]string(nil), def.Servers...)
	}

	unique := make(map[string]struct{}, len(names))
	auditByName := make(map[string]ActiveResolveAuditRecord, len(names))
	for _, raw := range names {
		name := canonicalDNSName(strings.TrimSpace(raw))
		if !IsResolvableDNSName(name) {
			if _, exists := auditByName[name]; !exists {
				auditByName[name] = ActiveResolveAuditRecord{DNSName: name, Status: "skipped_invalid"}
			}
			continue
		}
		unique[name] = struct{}{}
	}
	if len(unique) == 0 {
		audit := activeResolveAuditMapValues(auditByName)
		return []DNSNameIPv4Resolution{}, audit, nil
	}

	candidates := make([]string, 0, len(unique))
	for name := range unique {
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)

	if lookup == nil {
		resolver := makeResolver(opt.Servers, opt.Timeout)
		lookup = func(ctx context.Context, name string) ([]net.IP, error) {
			return resolver.LookupIP(ctx, "ip4", name)
		}
	}

	type result struct {
		name string
		ips  []string
		err  error
	}

	workers := min(opt.Workers, len(candidates), 32)
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	results := make(chan result, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case name, ok := <-jobs:
					if !ok {
						return
					}

					lookupCtx, cancel := context.WithTimeout(ctx, opt.Timeout)
					ips, err := lookup(lookupCtx, name)
					cancel()
					if err != nil {
						select {
						case <-ctx.Done():
							return
						case results <- result{name: name, err: err}:
						}
						continue
					}

					seen := make(map[string]struct{}, len(ips))
					ipv4s := make([]string, 0, len(ips))
					for _, ip := range ips {
						if ip4 := ip.To4(); ip4 != nil {
							s := ip4.String()
							if _, exists := seen[s]; exists {
								continue
							}
							seen[s] = struct{}{}
							ipv4s = append(ipv4s, s)
						}
					}
					sort.Strings(ipv4s)
					select {
					case <-ctx.Done():
						return
					case results <- result{name: name, ips: ipv4s}:
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, name := range candidates {
			select {
			case <-ctx.Done():
				return
			case jobs <- name:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]DNSNameIPv4Resolution, 0, len(candidates))
	for item := range results {
		record := ActiveResolveAuditRecord{DNSName: item.name, IPv4s: append([]string(nil), item.ips...)}
		if item.err != nil {
			record.Status = activeResolveErrorStatus(item.err)
			record.Error = item.err.Error()
			auditByName[item.name] = record
			continue
		}
		if len(item.ips) == 0 {
			record.Status = "no_ipv4"
			auditByName[item.name] = record
			continue
		}
		record.Status = "resolved"
		auditByName[item.name] = record
		out = append(out, DNSNameIPv4Resolution{DNSName: item.name, IPv4s: item.ips})
	}
	if err := ctx.Err(); err != nil {
		return nil, activeResolveAuditMapValues(auditByName), err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DNSName < out[j].DNSName })
	return out, activeResolveAuditMapValues(auditByName), nil
}

func activeResolveErrorStatus(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "error"
}

func activeResolveAuditMapValues(records map[string]ActiveResolveAuditRecord) []ActiveResolveAuditRecord {
	out := make([]ActiveResolveAuditRecord, 0, len(records))
	for _, record := range records {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DNSName < out[j].DNSName })
	return out
}

// WriteActiveResolveAuditCSV writes deterministic active-resolution outcomes.
func WriteActiveResolveAuditCSV(w io.Writer, records []ActiveResolveAuditRecord, opt ResolveUnresolvedOptions) error {
	def := DefaultResolveUnresolvedOptions()
	if opt.Timeout <= 0 {
		opt.Timeout = def.Timeout
	}
	if len(opt.Servers) == 0 {
		opt.Servers = append([]string(nil), def.Servers...)
	}

	rows := append([]ActiveResolveAuditRecord(nil), records...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].DNSName < rows[j].DNSName })
	csvWriter := csv.NewWriter(w)
	if err := csvWriter.Write([]string{
		"dns_name", "status", "configured_resolvers", "timeout_seconds", "ipv4_answers",
		"matrix_ips", "matrix_rows_completed", "error",
	}); err != nil {
		return fmt.Errorf("write active resolve CSV header: %w", err)
	}
	for _, row := range rows {
		if err := csvWriter.Write([]string{
			row.DNSName,
			row.Status,
			strings.Join(opt.Servers, ";"),
			strconv.FormatFloat(opt.Timeout.Seconds(), 'f', -1, 64),
			strings.Join(row.IPv4s, ";"),
			strings.Join(row.MatrixIPs, ";"),
			strconv.Itoa(row.MatrixRowsCompleted),
			row.Error,
		}); err != nil {
			return fmt.Errorf("write active resolve CSV row for %q: %w", row.DNSName, err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush active resolve CSV: %w", err)
	}
	return nil
}

// ResolveUnresolvedDNSTransactions:
//  1. finds DNS transactions with no resolved IPs
//  2. filters out non-real names (local/localhost/underscores/no-dot/...)
//  3. resolves names concurrently (IPv4 only)
//  4. injects resolved IPv4s into those transactions (with EvActiveResolve evidence)
//
// Returns:
//   - same tx slice (mutated in place) for convenience
//   - unresolved stats for output file (only those that are still unresolved or skipped)
func ResolveUnresolvedDNSTransactions(
	ctx context.Context,
	txs []*DNSTransaction,
	opt ResolveUnresolvedOptions,
) ([]*DNSTransaction, []DNSUnresolvedStat, error) {
	def := DefaultResolveUnresolvedOptions()
	if opt.Workers <= 0 {
		opt.Workers = def.Workers
	}
	if opt.Timeout <= 0 {
		opt.Timeout = def.Timeout
	}
	if len(opt.Servers) == 0 {
		opt.Servers = append([]string(nil), def.Servers...)
	}

	// Collect unresolved candidates by name (dedup), but retain all unresolved txs
	// for unresolved output later.
	nameToTxs := make(map[string][]*DNSTransaction)

	for _, tx := range txs {
		if tx == nil || tx.DNSName == "" {
			continue
		}
		if len(tx.ResolvedIPs) > 0 {
			continue
		}

		name := strings.TrimSuffix(strings.TrimSpace(tx.DNSName), ".")
		if name == "" {
			continue
		}

		// Only “real” names will be resolved, but “fake” ones should remain
		// in unresolved output (buildUnresolvedStatsFromTxs handles that).
		if !IsResolvableDNSName(name) {
			continue
		}

		nameToTxs[name] = append(nameToTxs[name], tx)
	}

	// If nothing to resolve, still emit unresolved list (existing behavior).
	if len(nameToTxs) == 0 {
		return txs, buildUnresolvedStatsFromTxs(txs), nil
	}

	names := make([]string, 0, len(nameToTxs))
	for n := range nameToTxs {
		names = append(names, n)
	}
	sort.Strings(names)

	type res struct {
		name string
		ips  []net.IP // v4 only
		err  error
	}

	total := len(names)
	done := 0
	resolved := 0
	progress.UpdateBar(0, total, fmt.Sprintf("resolved %d from %d", resolved, total))

	workers := opt.Workers
	if workers > total {
		workers = total
	}
	// Keep this conservative unless you later add backoff/retry; avoids DNS rate-limit pain.
	if workers > 32 {
		workers = 32
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	results := make(chan res, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		// Resolver per worker (cheap, avoids shared state contention)
		resolver := makeResolver(opt.Servers, opt.Timeout)

		go func(r *net.Resolver) {
			defer wg.Done()
			for name := range jobs {
				rctx, cancel := context.WithTimeout(ctx, opt.Timeout)
				addrs, err := r.LookupIPAddr(rctx, name)
				cancel()

				if err != nil {
					results <- res{name: name, err: err}
					continue
				}

				seen := make(map[string]struct{}, len(addrs))
				out := make([]net.IP, 0, len(addrs))
				for _, a := range addrs {
					ip4 := a.IP.To4()
					if ip4 == nil {
						continue
					}
					s := ip4.String()
					if _, ok := seen[s]; ok {
						continue
					}
					seen[s] = struct{}{}
					out = append(out, append(net.IP(nil), ip4...))
				}

				results <- res{name: name, ips: out}
			}
		}(resolver)
	}

	// Feed jobs
	go func() {
		defer close(jobs)
		for _, n := range names {
			select {
			case <-ctx.Done():
				return
			case jobs <- n:
			}
		}
	}()

	// Close results when workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect resolved results (resolve each name once)
	resolveMap := make(map[string][]net.IP, len(names))
	for r := range results {
		done++

		if r.err == nil && len(r.ips) > 0 {
			resolved++
			resolveMap[r.name] = r.ips
		}

		progress.UpdateBar(done, total, fmt.Sprintf("resolved %d from %d", resolved, total))
	}

	// Inject resolved IPv4s into still-unresolved txs (mutate in place)
	for name, lst := range nameToTxs {
		ips := resolveMap[name]
		if len(ips) == 0 {
			continue
		}
		for _, tx := range lst {
			// Only inject if still unresolved
			if tx == nil || len(tx.ResolvedIPs) > 0 {
				continue
			}
			// Preserve name source if not set (these txs originate from DNS query parsing)
			if tx.NameEvidence == EvNone {
				tx.NameEvidence = EvDNSAnswer
			}
			for _, ip := range ips {
				tx.AddResolvedIP(ip, EvActiveResolve)
			}
		}
	}

	// Return unresolved stats AFTER attempt (including “skipped” ones).
	return txs, buildUnresolvedStatsFromTxs(txs), nil
}

func buildUnresolvedStatsFromTxs(txs []*DNSTransaction) []DNSUnresolvedStat {
	type key struct {
		name   string
		issuer string
	}

	firstFile := make(map[key]string)

	for _, tx := range txs {
		if tx == nil || tx.DNSName == "" {
			continue
		}
		if len(tx.ResolvedIPs) > 0 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(tx.DNSName), ".")
		if name == "" {
			continue
		}
		issuer := ""
		if tx.IssuerIP != nil {
			issuer = tx.IssuerIP.String()
		}

		k := key{name: name, issuer: issuer}
		// include also non-real names (policy-skipped) in unresolved output
		if _, ok := firstFile[k]; !ok && tx.PCAPFile != "" {
			firstFile[k] = tx.PCAPFile
		}
	}

	if len(firstFile) == 0 {
		return nil
	}

	out := make([]DNSUnresolvedStat, 0, len(firstFile))
	for k, file := range firstFile {
		out = append(out, DNSUnresolvedStat{
			Name:          k.name,
			IssuerIP:      k.issuer,
			FirstPCAPFile: file,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].IssuerIP != out[j].IssuerIP {
			return out[i].IssuerIP < out[j].IssuerIP
		}
		return out[i].FirstPCAPFile < out[j].FirstPCAPFile
	})
	return out
}

// Optional helper for debugging / telemetry.
func (o ResolveUnresolvedOptions) String() string {
	return fmt.Sprintf("workers=%d timeout=%s servers=%v", o.Workers, o.Timeout, o.Servers)
}
