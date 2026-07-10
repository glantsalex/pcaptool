package dns

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type tlsCertProberFunc func(context.Context, TLSEndpoint) (TLSCertProbeResult, error)

func (f tlsCertProberFunc) Probe(ctx context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
	return f(ctx, endpoint)
}

type tlsCertTestTimeoutError struct{}

func (tlsCertTestTimeoutError) Error() string   { return "i/o timeout" }
func (tlsCertTestTimeoutError) Timeout() bool   { return true }
func (tlsCertTestTimeoutError) Temporary() bool { return true }

func TestProbeTLSCertificatesCandidatesClassificationAndDeterminism(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", Protocol: " TCP ", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: " 8.8.8.8 ", Protocol: "tcp", Port: 443, DNSName: "NONE", DNSSource: "NO ATTRIBUTION"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 8443, DNSSource: "mid-session"},
		{DestinationIP: "1.1.1.1", Protocol: "tcp", Port: 8883, DNSSource: "mid-session"},
		{DestinationIP: "9.9.9.9", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "11.0.0.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "10.0.0.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.4.4", Protocol: "udp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.4.4", Protocol: "tcp", Port: 443, DNSName: "known.example", DNSSource: "dns+synack"},
		{DestinationIP: "not-an-ip", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
	}
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 2*60*60))
	notAfter := notBefore.Add(24 * time.Hour)
	certByEndpoint := map[TLSEndpoint]*x509.Certificate{
		{IP: "8.8.8.8", Port: 443}: {
			Subject: pkix.Name{CommonName: " CN.Example.COM. "},
			Issuer:  pkix.Name{CommonName: " Example Issuer "},
			DNSNames: []string{
				"API.Example.COM.", "api.example.com", "*.wild.example.com", "router.local", " ",
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		{IP: "8.8.8.8", Port: 8443}: {
			DNSNames: []string{"b.example.com", "a.example.com"},
		},
		{IP: "1.1.1.1", Port: 8883}: {
			DNSNames: []string{"*.mqtt.example.com", "later.example.com", "router.internal"},
		},
		{IP: "9.9.9.9", Port: 443}: {
			Subject: pkix.Name{CommonName: "CN-Only.Example.COM."},
		},
		{IP: "11.0.0.1", Port: 443}: {
			Subject:  pkix.Name{CommonName: "router.local"},
			DNSNames: []string{"router.home", "reverse.arpa", "bad*name.example.com"},
		},
	}
	var mu sync.Mutex
	calls := make(map[TLSEndpoint]int)
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		mu.Lock()
		calls[endpoint]++
		mu.Unlock()
		return TLSCertProbeResult{Leaf: certByEndpoint[endpoint]}, nil
	})
	var progress [][2]int

	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{
		Workers: 3,
		Progress: func(processed, total int) {
			progress = append(progress, [2]int{processed, total})
		},
	})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	wantEndpoints := []TLSEndpoint{
		{IP: "1.1.1.1", Port: 8883},
		{IP: "8.8.8.8", Port: 443},
		{IP: "8.8.8.8", Port: 8443},
		{IP: "9.9.9.9", Port: 443},
		{IP: "11.0.0.1", Port: 443},
		{IP: "11.0.0.1", Port: 8443},
	}
	if len(records) != len(wantEndpoints) {
		t.Fatalf("record count = %d, want %d: %#v", len(records), len(wantEndpoints), records)
	}
	recordByEndpoint := make(map[TLSEndpoint]TLSCertLookupRecord, len(records))
	for i, record := range records {
		gotEndpoint := TLSEndpoint{IP: record.IP, Port: record.Port}
		if gotEndpoint != wantEndpoints[i] {
			t.Fatalf("record %d endpoint = %#v, want %#v", i, gotEndpoint, wantEndpoints[i])
		}
		recordByEndpoint[gotEndpoint] = record
	}
	for _, endpoint := range wantEndpoints {
		if calls[endpoint] != 1 {
			t.Fatalf("Probe(%#v) calls = %d, want 1", endpoint, calls[endpoint])
		}
	}

	single := recordByEndpoint[TLSEndpoint{IP: "8.8.8.8", Port: 443}]
	if single.Status != "used_cert" || single.Reason != "selected_first_san" || single.SelectedName != "api.example.com" || single.Source != "tls-cert-san+matrix" {
		t.Fatalf("single SAN record = %#v", single)
	}
	if single.SubjectCN != "cn.example.com" || single.IssuerCommonName != "Example Issuer" {
		t.Fatalf("certificate identity fields = %#v", single)
	}
	if single.DNSSANs != "api.example.com;api.example.com;*.wild.example.com;router.local" {
		t.Fatalf("logged SANs = %q", single.DNSSANs)
	}
	if single.NotBefore != notBefore.UTC().Format(time.RFC3339) || single.NotAfter != notAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("certificate times = %q / %q", single.NotBefore, single.NotAfter)
	}
	if record := recordByEndpoint[TLSEndpoint{IP: "8.8.8.8", Port: 8443}]; record.Reason != "selected_first_san" || record.SelectedName != "b.example.com" || record.Source != "tls-cert-san+matrix" {
		t.Fatalf("first of multiple SANs record = %#v", record)
	}
	if record := recordByEndpoint[TLSEndpoint{IP: "1.1.1.1", Port: 8883}]; record.Reason != "selected_first_san_wildcard_stripped" || record.SelectedName != "mqtt.example.com" || record.Source != "tls-cert-san+matrix" {
		t.Fatalf("wildcard SAN record = %#v", record)
	}
	if record := recordByEndpoint[TLSEndpoint{IP: "9.9.9.9", Port: 443}]; record.Reason != "selected_cn_no_san" || record.SelectedName != "cn-only.example.com" {
		t.Fatalf("CN fallback record = %#v", record)
	}
	if record := recordByEndpoint[TLSEndpoint{IP: "11.0.0.1", Port: 443}]; record.Reason != "no_dns_names" || record.SelectedName != "" || record.Source != "" {
		t.Fatalf("invalid SAN record = %#v", record)
	}
	const wantCompletedChains = 5
	if len(progress) != wantCompletedChains || progress[len(progress)-1] != [2]int{wantCompletedChains, wantCompletedChains} {
		t.Fatalf("progress = %#v", progress)
	}
}

func TestProbeTLSCertificatesProgressIsLiveAndDeduplicatesChains(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "1.1.1.1", Protocol: "tcp", Port: 5000, DNSSource: "mid-session"},
		{DestinationIP: " 1.1.1.1 ", Protocol: " TCP ", Port: 5000},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 8883, DNSSource: "mid-session"},
	}
	blockedStarted := make(chan struct{})
	releaseBlocked := make(chan struct{})
	progress := make(chan [2]int, 2)
	var mu sync.Mutex
	calls := make(map[TLSEndpoint]int)
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		mu.Lock()
		calls[endpoint]++
		mu.Unlock()
		if endpoint.IP == "8.8.8.8" {
			close(blockedStarted)
			<-releaseBlocked
		}
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"exact.example.com"}}}, nil
	})

	type probeResult struct {
		records []TLSCertLookupRecord
		err     error
	}
	resultCh := make(chan probeResult, 1)
	go func() {
		records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{
			Workers: 2,
			Progress: func(processed, total int) {
				progress <- [2]int{processed, total}
			},
		})
		resultCh <- probeResult{records: records, err: err}
	}()

	<-blockedStarted
	select {
	case got := <-progress:
		if got != [2]int{1, 2} {
			t.Fatalf("first live progress = %v, want [1 2]", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no progress reported while another unique chain was still blocked")
	}
	close(releaseBlocked)
	if got := <-progress; got != [2]int{2, 2} {
		t.Fatalf("final progress = %v, want [2 2]", got)
	}
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", result.err)
	}
	if len(result.records) != 2 {
		t.Fatalf("records = %#v, want two unique exact endpoint attempts", result.records)
	}
	for _, endpoint := range []TLSEndpoint{{IP: "1.1.1.1", Port: 5000}, {IP: "8.8.8.8", Port: 8883}} {
		if calls[endpoint] != 1 {
			t.Fatalf("Probe(%#v) calls = %d, want 1", endpoint, calls[endpoint])
		}
	}
}

func TestProbeTLSCertificatesErrorClassificationAndCancellation(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "1.1.1.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.4.4", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "9.9.9.9", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "11.0.0.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "12.0.0.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
	}
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		switch endpoint.IP {
		case "1.1.1.1":
			return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageConnect, Err: errors.New("refused")}
		case "8.8.8.8":
			return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageHandshake, Err: errors.New("bad record")}
		case "8.8.4.4":
			return TLSCertProbeResult{}, context.DeadlineExceeded
		case "9.9.9.9":
			return TLSCertProbeResult{}, nil
		case "12.0.0.1":
			return TLSCertProbeResult{}, &TLSCertProbeError{Stage: TLSCertProbeStageConnect, Err: tlsCertTestTimeoutError{}}
		default:
			return TLSCertProbeResult{}, errors.New("unexpected")
		}
	})
	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{Workers: 2})
	if err != nil {
		t.Fatalf("individual probe errors returned operation error: %v", err)
	}
	want := map[string][2]string{
		"1.1.1.1":  {"connect_error", "connect_failed"},
		"8.8.8.8":  {"tls_error", "handshake_failed"},
		"8.8.4.4":  {"timeout", "timeout"},
		"9.9.9.9":  {"no_certificate", "no_peer_cert"},
		"11.0.0.1": {"error", "probe_failed"},
		"12.0.0.1": {"timeout", "timeout"},
	}
	for _, record := range records {
		if got := [2]string{record.Status, record.Reason}; got != want[record.IP] {
			t.Fatalf("record for %s = %#v, want %#v", record.IP, got, want[record.IP])
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelingProber := tlsCertProberFunc(func(ctx context.Context, _ TLSEndpoint) (TLSCertProbeResult, error) {
		cancel()
		<-ctx.Done()
		return TLSCertProbeResult{}, ctx.Err()
	})
	_, err = ProbeTLSCertificates(ctx, entries[:1], cancelingProber, TLSCertLookupOptions{Workers: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation error = %v, want context.Canceled", err)
	}
}

func TestProbeTLSCertificatesPerEndpointTimeoutIsNonFatal(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"}}
	prober := tlsCertProberFunc(func(ctx context.Context, _ TLSEndpoint) (TLSCertProbeResult, error) {
		<-ctx.Done()
		return TLSCertProbeResult{}, ctx.Err()
	})
	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{Workers: 1, Timeout: time.Millisecond})
	if err != nil {
		t.Fatalf("per-endpoint timeout returned operation error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("timeout records = %#v", records)
	}
	for _, record := range records {
		if record.Status != "timeout" || record.Reason != "timeout" {
			t.Fatalf("timeout record = %#v", record)
		}
	}
}

func TestDefaultTLSCertLookupTimeoutIsFifteenSeconds(t *testing.T) {
	if defaultTLSCertLookupTimeout != 15*time.Second {
		t.Fatalf("defaultTLSCertLookupTimeout = %s, want 15s", defaultTLSCertLookupTimeout)
	}
}

func TestTLSCertProbePorts(t *testing.T) {
	tests := []struct {
		port uint16
		want []uint16
	}{
		{port: 5000, want: []uint16{5000, 443, 8443}},
		{port: 8883, want: []uint16{8883, 443, 8443}},
		{port: 443, want: []uint16{443, 8443}},
		{port: 8443, want: []uint16{8443, 443}},
		{port: 0, want: nil},
	}
	for _, tt := range tests {
		if got := tlsCertProbePorts(tt.port); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("tlsCertProbePorts(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestProbeTLSCertificatesUsesOrderedFallbackAndStopsOnUsableName(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "8.8.8.8", Protocol: " TCP ", Port: 5000, DNSSource: " Mid-Session "}}
	var calls []TLSEndpoint
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		calls = append(calls, endpoint)
		switch endpoint.Port {
		case 5000:
			return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"router.local"}}}, nil
		case 443:
			return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"fallback.example.com"}}}, nil
		default:
			t.Fatalf("unexpected probe after usable fallback: %#v", endpoint)
			return TLSCertProbeResult{}, nil
		}
	})

	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{Workers: 1})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	wantCalls := []TLSEndpoint{{IP: "8.8.8.8", Port: 5000}, {IP: "8.8.8.8", Port: 443}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("probe calls = %#v, want %#v", calls, wantCalls)
	}
	if len(records) != 2 {
		t.Fatalf("records = %#v, want two attempted endpoints", records)
	}
	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 1 || got[0].DNSName != "fallback.example.com" || got[0].DNSSource != "tls-cert-san+matrix-fallback" {
		t.Fatalf("fallback completion = %#v, decorated=%d", got, decorated)
	}
}

func TestProbeTLSCertificatesUsesExactCustomPortAndSkipsFallback(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000, DNSSource: "mid-session"}}
	var calls []TLSEndpoint
	records, err := ProbeTLSCertificates(context.Background(), entries, tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		calls = append(calls, endpoint)
		if endpoint.Port != 5000 {
			t.Fatalf("fallback port called after usable exact SAN: %#v", endpoint)
		}
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"exact-custom.example.com"}}}, nil
	}), TLSCertLookupOptions{Workers: 1})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	wantCalls := []TLSEndpoint{{IP: "8.8.8.8", Port: 5000}}
	if !reflect.DeepEqual(calls, wantCalls) || len(records) != 1 {
		t.Fatalf("calls=%#v records=%#v, want exact custom port only", calls, records)
	}
	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 1 || got[0].DNSName != "exact-custom.example.com" || got[0].DNSSource != "tls-cert-san+matrix" {
		t.Fatalf("exact custom-port completion = %#v, decorated=%d", got, decorated)
	}
}

func TestProbeTLSCertificatesFallsThroughExactAnd443To8443(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000, DNSSource: "mid-session"}}
	var calls []TLSEndpoint
	records, err := ProbeTLSCertificates(context.Background(), entries, tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		calls = append(calls, endpoint)
		switch endpoint.Port {
		case 5000:
			return TLSCertProbeResult{}, errors.New("connection refused")
		case 443:
			return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"router.local"}}}, nil
		case 8443:
			return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"last-fallback.example.com"}}}, nil
		default:
			t.Fatalf("unexpected endpoint: %#v", endpoint)
			return TLSCertProbeResult{}, nil
		}
	}), TLSCertLookupOptions{Workers: 1})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	wantCalls := []TLSEndpoint{
		{IP: "8.8.8.8", Port: 5000},
		{IP: "8.8.8.8", Port: 443},
		{IP: "8.8.8.8", Port: 8443},
	}
	if !reflect.DeepEqual(calls, wantCalls) || len(records) != 3 {
		t.Fatalf("calls=%#v records=%#v, want full fallback chain", calls, records)
	}
	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 1 || got[0].DNSName != "last-fallback.example.com" || got[0].DNSSource != "tls-cert-san+matrix-fallback" {
		t.Fatalf("8443 fallback completion = %#v, decorated=%d", got, decorated)
	}
}

func TestProbeTLSCertificatesUsesExact8883AndStops(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "1.1.1.1", Protocol: "tcp", Port: 8883}}
	var calls []TLSEndpoint
	records, err := ProbeTLSCertificates(context.Background(), entries, tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		calls = append(calls, endpoint)
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"mqtt.example.com"}}}, nil
	}), TLSCertLookupOptions{Workers: 1})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	wantCalls := []TLSEndpoint{{IP: "1.1.1.1", Port: 8883}}
	if !reflect.DeepEqual(calls, wantCalls) || len(records) != 1 {
		t.Fatalf("calls=%#v records=%#v, want exact 8883 only", calls, records)
	}
	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 1 || got[0].DNSName != "mqtt.example.com" || got[0].DNSSource != "tls-cert-san+matrix" {
		t.Fatalf("exact 8883 completion = %#v, decorated=%d", got, decorated)
	}
}

func TestProbeTLSCertificatesSharesExactEndpointAttemptsByIPAndPort(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443},
	}
	var mu sync.Mutex
	calls := make(map[TLSEndpoint]int)
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		mu.Lock()
		calls[endpoint]++
		mu.Unlock()
		if endpoint.Port == 5000 {
			return TLSCertProbeResult{}, errors.New("not TLS")
		}
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"shared.example.com"}}}, nil
	})
	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{Workers: 2})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %#v, want one per exact endpoint", records)
	}
	for _, endpoint := range []TLSEndpoint{{IP: "8.8.8.8", Port: 5000}, {IP: "8.8.8.8", Port: 443}} {
		if calls[endpoint] != 1 {
			t.Fatalf("Probe(%#v) calls = %d, want 1", endpoint, calls[endpoint])
		}
	}
}

func TestProbeTLSCertificatesCacheKeyIncludesPortForSameIPRows(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000, DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 8883, DNSSource: "mid-session"},
	}
	var mu sync.Mutex
	calls := make(map[TLSEndpoint]int)
	prober := tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		mu.Lock()
		calls[endpoint]++
		mu.Unlock()
		var name string
		switch endpoint.Port {
		case 5000:
			name = "custom.example.com"
		case 8883:
			name = "mqtt.example.com"
		default:
			t.Fatalf("unexpected fallback probe: %#v", endpoint)
		}
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{name}}}, nil
	})
	records, err := ProbeTLSCertificates(context.Background(), entries, prober, TLSCertLookupOptions{Workers: 2})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	for _, endpoint := range []TLSEndpoint{{IP: "8.8.8.8", Port: 5000}, {IP: "8.8.8.8", Port: 8883}} {
		if calls[endpoint] != 1 {
			t.Fatalf("Probe(%#v) calls = %d, want 1", endpoint, calls[endpoint])
		}
	}
	if len(records) != 2 {
		t.Fatalf("records = %#v, want two exact endpoints", records)
	}
	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 2 {
		t.Fatalf("decorated = %d, want 2: %#v", decorated, got)
	}
	if got[0].DNSName != "custom.example.com" || got[0].DNSSource != "tls-cert-san+matrix" {
		t.Fatalf("tcp/5000 row = %#v", got[0])
	}
	if got[1].DNSName != "mqtt.example.com" || got[1].DNSSource != "tls-cert-san+matrix" {
		t.Fatalf("tcp/8883 row = %#v", got[1])
	}
}

func TestProbeTLSCertificatesStrictCandidateEligibility(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000},
		{DestinationIP: "8.8.8.8", Protocol: "udp", Port: 5000},
		{DestinationIP: "10.0.0.1", Protocol: "tcp", Port: 5000},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000, DNSName: "known.example.com"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 5000, DNSSource: "csv+mid"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 0},
	}
	var calls []TLSEndpoint
	_, err := ProbeTLSCertificates(context.Background(), entries, tlsCertProberFunc(func(_ context.Context, endpoint TLSEndpoint) (TLSCertProbeResult, error) {
		calls = append(calls, endpoint)
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"exact.example.com"}}}, nil
	}), TLSCertLookupOptions{Workers: 2})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	want := []TLSEndpoint{{IP: "8.8.8.8", Port: 5000}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("eligible probe calls = %#v, want %#v", calls, want)
	}
}

func TestTLSCertProbeCacheWaitHonorsContext(t *testing.T) {
	cache := newTLSCertProbeCache()
	started := make(chan struct{})
	release := make(chan struct{})
	prober := tlsCertProberFunc(func(context.Context, TLSEndpoint) (TLSCertProbeResult, error) {
		close(started)
		<-release
		return TLSCertProbeResult{}, nil
	})
	endpoint := TLSEndpoint{IP: "8.8.8.8", Port: 443}
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		_, _ = cache.probe(context.Background(), endpoint, prober, time.Second)
	}()
	<-started
	waitCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.probe(waitCtx, endpoint, prober, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cache probe error = %v, want context.Canceled", err)
	}
	close(release)
	<-ownerDone
}

func TestWriteTLSCertLookupCSVDeterministicNumericSortAndHeaderOnly(t *testing.T) {
	records := []TLSCertLookupRecord{
		{IP: "11.0.0.1", Port: 443, Status: "used_cert", Reason: "no_dns_names"},
		{IP: "8.8.8.8", Port: 8443, Status: "tls_error", Reason: "handshake_failed", Error: "bad, record"},
		{IP: "8.8.8.8", Port: 443, Status: "used_cert", SelectedName: "api.example.com", Reason: "selected_first_san", Source: "tls-cert-san+matrix"},
	}
	var first bytes.Buffer
	if err := WriteTLSCertLookupCSV(&first, records); err != nil {
		t.Fatalf("WriteTLSCertLookupCSV() error = %v", err)
	}
	var second bytes.Buffer
	if err := WriteTLSCertLookupCSV(&second, records); err != nil {
		t.Fatalf("second WriteTLSCertLookupCSV() error = %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("TLS certificate CSV is not deterministic")
	}
	wantHeader := "ip,port,status,selected_name,reason,subject_cn,dns_sans,issuer_common_name,not_before,not_after,error,source\n"
	if !strings.HasPrefix(first.String(), wantHeader+"8.8.8.8,443,") {
		t.Fatalf("CSV header/order = %q", first.String())
	}
	if !strings.Contains(first.String(), `"bad, record"`) {
		t.Fatalf("CSV did not escape error: %q", first.String())
	}
	var empty bytes.Buffer
	if err := WriteTLSCertLookupCSV(&empty, nil); err != nil {
		t.Fatalf("header-only WriteTLSCertLookupCSV() error = %v", err)
	}
	if empty.String() != wantHeader {
		t.Fatalf("header-only CSV = %q, want %q", empty.String(), wantHeader)
	}
}

func TestTLSCertRecordForOutcomeRejectsInvalidEndpoint(t *testing.T) {
	record := tlsCertRecordForOutcome(tlsCertProbeOutcome{endpoint: TLSEndpoint{IP: "bad", Port: 443}})
	if record.Status != "skipped" || record.Reason != "invalid_endpoint" {
		t.Fatalf("invalid endpoint record = %#v", record)
	}
}

func TestTLSCertRecordForOutcomeInvalidWildcardIsNotWildcardOnly(t *testing.T) {
	record := tlsCertRecordForOutcome(tlsCertProbeOutcome{
		endpoint: TLSEndpoint{IP: "8.8.8.8", Port: 443},
		result: TLSCertProbeResult{Leaf: &x509.Certificate{
			DNSNames: []string{"foo*bar.example.com"},
		}},
	})
	if record.Status != "used_cert" || record.Reason != "no_dns_names" || record.SelectedName != "" {
		t.Fatalf("invalid wildcard record = %#v", record)
	}
	if record.DNSSANs != "foo*bar.example.com" {
		t.Fatalf("invalid wildcard missing from diagnostic SAN log: %#v", record)
	}
}

func TestTLSCertRecordForOutcomeCNFallbackAfterUnusableSANs(t *testing.T) {
	tests := []struct {
		name       string
		dnsNames   []string
		wantReason string
		wantName   string
	}{
		{
			name:       "empty SAN entries allow CN fallback",
			dnsNames:   []string{"", "  ", "."},
			wantReason: "selected_cn_no_san",
			wantName:   "cn.example.com",
		},
		{
			name:       "nonempty invalid SAN allows CN fallback",
			dnsNames:   []string{"", "router.local"},
			wantReason: "selected_cn_no_san",
			wantName:   "cn.example.com",
		},
		{
			name:       "malformed wildcards allow CN fallback",
			dnsNames:   []string{"*", "*.", "foo*bar.example.com", "*.*.example.com"},
			wantReason: "selected_cn_no_san",
			wantName:   "cn.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := tlsCertRecordForOutcome(tlsCertProbeOutcome{
				endpoint: TLSEndpoint{IP: "8.8.8.8", Port: 443},
				result: TLSCertProbeResult{Leaf: &x509.Certificate{
					Subject:  pkix.Name{CommonName: "CN.Example.COM."},
					DNSNames: tt.dnsNames,
				}},
			})
			wantSource := ""
			if tt.wantName != "" {
				wantSource = "tls-cert-san+matrix"
			}
			if record.Status != "used_cert" || record.Reason != tt.wantReason || record.SelectedName != tt.wantName || record.Source != wantSource {
				t.Fatalf("record = %#v, want reason %q selected name %q", record, tt.wantReason, tt.wantName)
			}
		})
	}
}

func TestCompleteTopologyWithTLSCertificatesDecoratesOnlyExactEligibleRows(t *testing.T) {
	entries := []TopologyEntry{
		{IssuerIP: "10.0.0.1", DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{IssuerIP: "10.0.0.2", DestinationIP: " 8.8.8.8 ", Protocol: " TCP ", Port: 443, DNSName: "NONE", DNSSource: "NO ATTRIBUTION"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 8443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSName: "known.example", DNSSource: "dns+synack"},
		{DestinationIP: "8.8.8.8", Protocol: "udp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 9443, DNSSource: "mid-session"},
		{DestinationIP: "10.0.0.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
		{DestinationIP: "1.1.1.1", Protocol: "tcp", Port: 443, DNSSource: "mid-session"},
	}
	records := []TLSCertLookupRecord{
		{IP: "8.8.8.8", Port: 443, Status: "used_cert", SelectedName: "CERT.Example.COM.", Source: "tls-cert-san+matrix"},
		{IP: " 8.8.8.8 ", Port: 443, Status: "used_cert", SelectedName: "cert.example.com"},
		{IP: "8.8.8.8", Port: 8443, Status: "used_cert", SelectedName: "one.example.com"},
		{IP: "8.8.8.8", Port: 8443, Status: "used_cert", SelectedName: "two.example.com"},
		{IP: "1.1.1.1", Port: 443, Status: "tls_error", SelectedName: "must-not-apply.example.com"},
		{IP: "10.0.0.1", Port: 443, Status: "used_cert", SelectedName: "private.example.com"},
	}
	original := append([]TopologyEntry(nil), entries...)

	got, decorated := CompleteTopologyWithTLSCertificates(entries, records)
	if decorated != 3 {
		t.Fatalf("decorated rows = %d, want 3", decorated)
	}
	if got[0].DNSName != "cert.example.com" || got[0].DNSSource != "tls-cert-san+matrix" {
		t.Fatalf("exact-port decorated row = %#v", got[0])
	}
	for _, i := range []int{2, 5} {
		if got[i].DNSName != "cert.example.com" || got[i].DNSSource != "tls-cert-san+matrix-fallback" {
			t.Fatalf("fallback decorated row %d = %#v", i, got[i])
		}
	}
	for _, i := range []int{1, 3, 4, 6, 7} {
		if got[i] != entries[i] {
			t.Fatalf("row %d unexpectedly changed: got %#v want %#v", i, got[i], entries[i])
		}
	}
	if !reflect.DeepEqual(entries, original) {
		t.Fatalf("input entries mutated: got %#v want %#v", entries, original)
	}
}

func TestProbeTLSCertificatesDoesNotMutateEntries(t *testing.T) {
	entries := []TopologyEntry{{DestinationIP: "8.8.8.8", Protocol: "tcp", Port: 443, DNSSource: "mid-session"}}
	original := append([]TopologyEntry(nil), entries...)
	_, err := ProbeTLSCertificates(context.Background(), entries, tlsCertProberFunc(func(context.Context, TLSEndpoint) (TLSCertProbeResult, error) {
		return TLSCertProbeResult{Leaf: &x509.Certificate{DNSNames: []string{"api.example.com"}}}, nil
	}), TLSCertLookupOptions{})
	if err != nil {
		t.Fatalf("ProbeTLSCertificates() error = %v", err)
	}
	if !reflect.DeepEqual(entries, original) {
		t.Fatalf("entries mutated: got %#v, want %#v", entries, original)
	}
}
