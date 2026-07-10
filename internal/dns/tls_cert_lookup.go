// Copyright © 2025 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLSEndpoint identifies one TLS probe target.
type TLSEndpoint struct {
	IP   string
	Port uint16
}

// TLSCertProbeResult contains the leaf certificate presented by an endpoint.
type TLSCertProbeResult struct {
	Leaf *x509.Certificate
}

// TLSCertProber probes an endpoint without affecting topology attribution.
type TLSCertProber interface {
	Probe(context.Context, TLSEndpoint) (TLSCertProbeResult, error)
}

// TLSCertLookupOptions controls bounded certificate probing.
type TLSCertLookupOptions struct {
	Workers  int
	Timeout  time.Duration
	Progress func(processed, total int)
}

// TLSCertLookupRecord is one deterministic audit row per probed endpoint.
type TLSCertLookupRecord struct {
	IP               string
	Port             uint16
	Status           string
	SelectedName     string
	Reason           string
	SubjectCN        string
	DNSSANs          string
	IssuerCommonName string
	NotBefore        string
	NotAfter         string
	Error            string
	Source           string
}

// TLSCertProbeStage identifies where a network probe failed.
type TLSCertProbeStage string

const (
	TLSCertProbeStageConnect   TLSCertProbeStage = "connect"
	TLSCertProbeStageHandshake TLSCertProbeStage = "handshake"
)

// TLSCertProbeError preserves the stage of a network probe failure.
type TLSCertProbeError struct {
	Stage TLSCertProbeStage
	Err   error
}

func (e *TLSCertProbeError) Error() string {
	if e == nil {
		return "TLS certificate probe error"
	}
	return fmt.Sprintf("TLS certificate probe %s: %v", e.Stage, e.Err)
}

func (e *TLSCertProbeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

const defaultTLSCertLookupTimeout = 15 * time.Second

type networkTLSCertProber struct{}

func (networkTLSCertProber) Probe(ctx context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
	ip, ok := canonicalIPv4String(endpoint.IP)
	if !ok || endpoint.Port == 0 {
		return TLSCertProbeResult{}, fmt.Errorf("invalid TLS endpoint %q:%d", endpoint.IP, endpoint.Port)
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(endpoint.Port))))
	if err != nil {
		return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageConnect, Err: err}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageConnect, Err: err}
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "",
		// This probe records the certificate presented by an IP-only endpoint;
		// it does not authenticate or trust that certificate for application use.
		InsecureSkipVerify: true, //nolint:gosec -- diagnostic-only certificate capture
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageHandshake, Err: err}
	}
	peerCertificates := tlsConn.ConnectionState().PeerCertificates
	if len(peerCertificates) == 0 {
		return TLSCertProbeResult{}, nil
	}
	return TLSCertProbeResult{Leaf: peerCertificates[0]}, nil
}

type tlsCertProbeOutcome struct {
	endpoint TLSEndpoint
	result   TLSCertProbeResult
	err      error
}

type tlsCertProbeCall struct {
	done    chan struct{}
	outcome tlsCertProbeOutcome
}

type tlsCertProbeCache struct {
	mu    sync.Mutex
	calls map[TLSEndpoint]*tlsCertProbeCall
}

func newTLSCertProbeCache() *tlsCertProbeCache {
	return &tlsCertProbeCache{calls: make(map[TLSEndpoint]*tlsCertProbeCall)}
}

func (c *tlsCertProbeCache) probe(
	ctx context.Context,
	endpoint TLSEndpoint,
	prober TLSCertProber,
	timeout time.Duration,
) (tlsCertProbeOutcome, error) {
	if err := ctx.Err(); err != nil {
		return tlsCertProbeOutcome{}, err
	}
	c.mu.Lock()
	call := c.calls[endpoint]
	if call == nil {
		call = &tlsCertProbeCall{done: make(chan struct{})}
		c.calls[endpoint] = call
		c.mu.Unlock()

		endpointCtx, cancel := context.WithTimeout(ctx, timeout)
		result, err := prober.Probe(endpointCtx, endpoint)
		cancel()
		outcome := tlsCertProbeOutcome{endpoint: endpoint, result: result, err: err}

		c.mu.Lock()
		call.outcome = outcome
		close(call.done)
		c.mu.Unlock()
		return outcome, nil
	}
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return tlsCertProbeOutcome{}, ctx.Err()
	case <-call.done:
		return call.outcome, nil
	}
}

func (c *tlsCertProbeCache) outcomes() []tlsCertProbeOutcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	outcomes := make([]tlsCertProbeOutcome, 0, len(c.calls))
	for _, call := range c.calls {
		select {
		case <-call.done:
			outcomes = append(outcomes, call.outcome)
		default:
		}
	}
	return outcomes
}

// ProbeTLSCertificates probes unique unresolved public TLS endpoints and
// returns deterministic audit records. It never mutates or returns topology.
// Individual endpoint failures are records; parent cancellation is the only
// operation-level error.
func ProbeTLSCertificates(
	ctx context.Context,
	entries []TopologyEntry,
	prober TLSCertProber,
	options TLSCertLookupOptions,
) ([]TLSCertLookupRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type probeChain struct {
		ip    string
		ports []uint16
	}
	chainByEndpoint := make(map[TLSEndpoint]probeChain, len(entries))
	for _, entry := range entries {
		ip, ok := tlsCertCandidateIP(entry)
		if !ok {
			continue
		}
		endpoint := TLSEndpoint{IP: ip, Port: entry.Port}
		chainByEndpoint[endpoint] = probeChain{ip: ip, ports: tlsCertProbePorts(entry.Port)}
	}
	if len(chainByEndpoint) == 0 {
		return []TLSCertLookupRecord{}, nil
	}
	chainEndpoints := make([]TLSEndpoint, 0, len(chainByEndpoint))
	for endpoint := range chainByEndpoint {
		chainEndpoints = append(chainEndpoints, endpoint)
	}
	sortTLSEndpoints(chainEndpoints)
	chains := make([]probeChain, 0, len(chainEndpoints))
	for _, endpoint := range chainEndpoints {
		chains = append(chains, chainByEndpoint[endpoint])
	}
	if prober == nil {
		prober = networkTLSCertProber{}
	}

	workers := options.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0) * 8
		if workers < 16 {
			workers = 16
		}
		if workers > 128 {
			workers = 128
		}
	}
	if workers > len(chains) {
		workers = len(chains)
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTLSCertLookupTimeout
	}

	jobs := make(chan probeChain, workers)
	completedChains := make(chan struct{}, workers)
	cache := newTLSCertProbeCache()
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case chain, ok := <-jobs:
					if !ok {
						return
					}
					for _, port := range chain.ports {
						outcome, err := cache.probe(ctx, TLSEndpoint{IP: chain.ip, Port: port}, prober, timeout)
						if err != nil {
							return
						}
						if tlsCertRecordForOutcome(outcome).SelectedName != "" {
							break
						}
					}
					select {
					case <-ctx.Done():
						return
					case completedChains <- struct{}{}:
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, chain := range chains {
			select {
			case <-ctx.Done():
				return
			case jobs <- chain:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(completedChains)
	}()
	processed := 0
	for range completedChains {
		processed++
		if options.Progress != nil {
			options.Progress(processed, len(chains))
		}
	}

	outcomes := cache.outcomes()
	records := make([]TLSCertLookupRecord, 0, len(outcomes))
	for _, outcome := range outcomes {
		records = append(records, tlsCertRecordForOutcome(outcome))
	}
	sortTLSCertRecords(records)
	if err := ctx.Err(); err != nil {
		return records, err
	}
	return records, nil
}

func tlsCertCandidateIP(entry TopologyEntry) (string, bool) {
	if strings.ToLower(strings.TrimSpace(entry.Protocol)) != "tcp" {
		return "", false
	}
	if entry.Port == 0 || strings.TrimSpace(entry.DNSName) != "" {
		return "", false
	}
	source := strings.ToLower(strings.TrimSpace(entry.DNSSource))
	if source != "" && source != "mid-session" {
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

func tlsCertProbePorts(rowPort uint16) []uint16 {
	if rowPort == 0 {
		return nil
	}
	ports := make([]uint16, 0, 3)
	seen := make(map[uint16]struct{}, 3)
	for _, port := range []uint16{rowPort, 443, 8443} {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports
}

func tlsCertRecordForOutcome(outcome tlsCertProbeOutcome) TLSCertLookupRecord {
	record := TLSCertLookupRecord{IP: outcome.endpoint.IP, Port: outcome.endpoint.Port}
	if _, ok := canonicalIPv4String(outcome.endpoint.IP); !ok || outcome.endpoint.Port == 0 {
		record.Status = "skipped"
		record.Reason = "invalid_endpoint"
		return record
	}
	if outcome.err != nil {
		record.Error = outcome.err.Error()
		if isTLSCertTimeout(outcome.err) {
			record.Status = "timeout"
			record.Reason = "timeout"
			return record
		}
		var stageErr *TLSCertProbeError
		if errors.As(outcome.err, &stageErr) {
			switch stageErr.Stage {
			case TLSCertProbeStageConnect:
				record.Status = "connect_error"
				record.Reason = "connect_failed"
				return record
			case TLSCertProbeStageHandshake:
				record.Status = "tls_error"
				record.Reason = "handshake_failed"
				return record
			}
		}
		record.Status = "error"
		record.Reason = "probe_failed"
		return record
	}
	if outcome.result.Leaf == nil {
		record.Status = "no_certificate"
		record.Reason = "no_peer_cert"
		return record
	}

	cert := outcome.result.Leaf
	record.Status = "used_cert"
	record.SubjectCN = canonicalCertificateDNSName(cert.Subject.CommonName)
	record.IssuerCommonName = strings.TrimSpace(cert.Issuer.CommonName)
	if !cert.NotBefore.IsZero() {
		record.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	}
	if !cert.NotAfter.IsZero() {
		record.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	allSANs := canonicalCertificateNamesInOrder(cert.DNSNames)
	record.DNSSANs = strings.Join(allSANs, ";")
	for _, name := range allSANs {
		if isUsableTLSCertificateName(name) {
			record.SelectedName = name
			record.Reason = "selected_first_san"
			break
		}
		if isUsableTLSCertificateWildcardName(name) {
			record.SelectedName = strings.TrimPrefix(name, "*.")
			record.Reason = "selected_first_san_wildcard_stripped"
			break
		}
	}
	if record.SelectedName != "" {
		record.Source = "tls-cert-san+matrix"
	} else if isUsableTLSCertificateName(record.SubjectCN) && !strings.Contains(record.SubjectCN, "*") {
		record.SelectedName = record.SubjectCN
		record.Reason = "selected_cn_no_san"
		record.Source = "tls-cert-san+matrix"
	} else {
		record.Reason = "no_dns_names"
	}
	return record
}

func canonicalCertificateDNSName(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(name), ".")))
}

func canonicalCertificateNamesInOrder(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = canonicalCertificateDNSName(name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func isUsableTLSCertificateName(name string) bool {
	if !IsResolvableDNSName(name) || strings.Contains(name, "*") {
		return false
	}
	for _, suffix := range []string{"local", "internal", "lan", "home", "arpa"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return false
		}
	}
	return true
}

func isUsableTLSCertificateWildcardName(name string) bool {
	if !strings.HasPrefix(name, "*.") || strings.Count(name, "*") != 1 {
		return false
	}
	return isUsableTLSCertificateName(strings.TrimPrefix(name, "*."))
}

func isTLSCertTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// CompleteTopologyWithTLSCertificates decorates otherwise-unattributed TLS
// topology rows from uniquely selected certificate labels. It returns a copy,
// never overwrites existing attribution, and reports the number of rows changed.
func CompleteTopologyWithTLSCertificates(entries []TopologyEntry, records []TLSCertLookupRecord) ([]TopologyEntry, int) {
	out := append([]TopologyEntry(nil), entries...)
	selectedByEndpoint := make(map[TLSEndpoint]map[string]struct{})
	for _, record := range records {
		if strings.TrimSpace(record.Status) != "used_cert" {
			continue
		}
		name := canonicalCertificateDNSName(record.SelectedName)
		if !isUsableTLSCertificateName(name) || strings.Contains(name, "*") || record.Port == 0 {
			continue
		}
		ip, ok := canonicalIPv4String(record.IP)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !isPublicIPv4(addr) {
			continue
		}
		endpoint := TLSEndpoint{IP: ip, Port: record.Port}
		names := selectedByEndpoint[endpoint]
		if names == nil {
			names = make(map[string]struct{}, 1)
			selectedByEndpoint[endpoint] = names
		}
		names[name] = struct{}{}
	}

	decorated := 0
	for i := range out {
		ip, ok := tlsCertCandidateIP(out[i])
		if !ok {
			continue
		}
		for _, port := range tlsCertProbePorts(out[i].Port) {
			names := selectedByEndpoint[TLSEndpoint{IP: ip, Port: port}]
			if len(names) != 1 {
				continue
			}
			for name := range names {
				out[i].DNSName = name
				if port == out[i].Port {
					out[i].DNSSource = "tls-cert-san+matrix"
				} else {
					out[i].DNSSource = "tls-cert-san+matrix-fallback"
				}
				decorated++
			}
			break
		}
	}
	return out, decorated
}

func sortTLSEndpoints(endpoints []TLSEndpoint) {
	sort.Slice(endpoints, func(i, j int) bool {
		left := netip.MustParseAddr(endpoints[i].IP)
		right := netip.MustParseAddr(endpoints[j].IP)
		if cmp := left.Compare(right); cmp != 0 {
			return cmp < 0
		}
		return endpoints[i].Port < endpoints[j].Port
	})
}

func sortTLSCertRecords(records []TLSCertLookupRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		left, leftErr := netip.ParseAddr(records[i].IP)
		right, rightErr := netip.ParseAddr(records[j].IP)
		if leftErr == nil && rightErr == nil {
			if cmp := left.Compare(right); cmp != 0 {
				return cmp < 0
			}
		} else if records[i].IP != records[j].IP {
			return records[i].IP < records[j].IP
		}
		return records[i].Port < records[j].Port
	})
}

// WriteTLSCertLookupCSV writes deterministic TLS certificate audit records.
func WriteTLSCertLookupCSV(w io.Writer, records []TLSCertLookupRecord) error {
	rows := append([]TLSCertLookupRecord(nil), records...)
	sortTLSCertRecords(rows)
	csvWriter := csv.NewWriter(w)
	if err := csvWriter.Write([]string{
		"ip", "port", "status", "selected_name", "reason", "subject_cn", "dns_sans",
		"issuer_common_name", "not_before", "not_after", "error", "source",
	}); err != nil {
		return fmt.Errorf("write TLS certificate CSV header: %w", err)
	}
	for _, row := range rows {
		if err := csvWriter.Write([]string{
			row.IP,
			strconv.FormatUint(uint64(row.Port), 10),
			row.Status,
			row.SelectedName,
			row.Reason,
			row.SubjectCN,
			row.DNSSANs,
			row.IssuerCommonName,
			row.NotBefore,
			row.NotAfter,
			row.Error,
			row.Source,
		}); err != nil {
			return fmt.Errorf("write TLS certificate CSV row for %s:%d: %w", row.IP, row.Port, err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush TLS certificate CSV: %w", err)
	}
	return nil
}
