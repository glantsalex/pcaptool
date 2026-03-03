// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
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
	if strings.HasSuffix(ls, ".local") {
		return false
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
