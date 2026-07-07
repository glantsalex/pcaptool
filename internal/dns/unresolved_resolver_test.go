package dns

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsResolvableDNSNameStrictSafeCandidates(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "api.example.com", want: true},
		{name: "API.Example.COM.", want: true},
		{name: "localhost"},
		{name: "printer"},
		{name: "host.local"},
		{name: "host.loc"},
		{name: "host.internal"},
		{name: "host.eth0"},
		{name: "1.0.0.127.in-addr.arpa"},
		{name: "0.8.e.f.ip6.arpa"},
		{name: "in-addr.arpa"},
		{name: "ip6.arpa"},
		{name: "bad_name.example"},
		{name: "-bad.example"},
		{name: "bad-.example"},
		{name: "bad..example"},
		{name: strings.Repeat("a", 64) + ".example.com"},
		{name: strings.Repeat("a.", 126) + "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsResolvableDNSName(tt.name); got != tt.want {
				t.Fatalf("IsResolvableDNSName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestResolveDNSNamesIPv4DoesNotLookupUnsafeCandidates(t *testing.T) {
	var calls atomic.Int32
	got, err := ResolveDNSNamesIPv4(
		context.Background(),
		[]string{
			"localhost",
			"printer",
			"host.local",
			"host.loc",
			"host.internal",
			"host.eth0",
			"1.0.0.127.in-addr.arpa",
			"bad_name.example",
		},
		ResolveUnresolvedOptions{Workers: 8, Timeout: time.Second},
		func(context.Context, string) ([]net.IP, error) {
			calls.Add(1)
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
	)
	if err != nil {
		t.Fatalf("ResolveDNSNamesIPv4: %v", err)
	}
	if len(got) != 0 || calls.Load() != 0 {
		t.Fatalf("unsafe candidates produced resolutions=%#v lookup_calls=%d", got, calls.Load())
	}
}

func TestResolveDNSNamesIPv4CanonicalDeterministicAndFailureTolerant(t *testing.T) {
	lookup := func(_ context.Context, name string) ([]net.IP, error) {
		switch name {
		case "a.example.com":
			time.Sleep(10 * time.Millisecond)
			return []net.IP{
				net.ParseIP("9.9.9.9"),
				net.ParseIP("2001:db8::1"),
				net.ParseIP("1.1.1.1"),
				net.ParseIP("9.9.9.9"),
			}, nil
		case "b.example.com":
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		case "error.example.com":
			return nil, errors.New("lookup failed")
		default:
			t.Fatalf("unexpected lookup for %q", name)
			return nil, nil
		}
	}

	got, err := ResolveDNSNamesIPv4(
		context.Background(),
		[]string{
			" B.Example.COM. ",
			"a.example.com",
			"A.EXAMPLE.COM",
			"host.local",
			"error.example.com",
		},
		ResolveUnresolvedOptions{Workers: 4, Timeout: time.Second},
		lookup,
	)
	if err != nil {
		t.Fatalf("ResolveDNSNamesIPv4: %v", err)
	}
	want := []DNSNameIPv4Resolution{
		{DNSName: "a.example.com", IPv4s: []string{"1.1.1.1", "9.9.9.9"}},
		{DNSName: "b.example.com", IPv4s: []string{"8.8.8.8"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolutions = %#v, want %#v", got, want)
	}
}

func TestResolveDNSNamesIPv4BoundsConcurrency(t *testing.T) {
	var current, maximum atomic.Int32
	lookup := func(_ context.Context, _ string) ([]net.IP, error) {
		n := current.Add(1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		current.Add(-1)
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}

	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	got, err := ResolveDNSNamesIPv4(
		context.Background(),
		names,
		ResolveUnresolvedOptions{Workers: 100, Timeout: time.Second},
		lookup,
	)
	if err != nil {
		t.Fatalf("ResolveDNSNamesIPv4: %v", err)
	}
	if len(got) != len(names) {
		t.Fatalf("len(resolutions) = %d, want %d", len(got), len(names))
	}
	if max := maximum.Load(); max < 2 || max > 32 {
		t.Fatalf("maximum concurrent lookups = %d, want 2..32", max)
	}
}

func TestResolveDNSNamesIPv4PerNameTimeoutIsNonFatal(t *testing.T) {
	lookup := func(ctx context.Context, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	got, err := ResolveDNSNamesIPv4(
		context.Background(),
		[]string{"slow.example.com"},
		ResolveUnresolvedOptions{Workers: 1, Timeout: 10 * time.Millisecond},
		lookup,
	)
	if err != nil {
		t.Fatalf("ResolveDNSNamesIPv4 returned run error for lookup timeout: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("timed-out lookup returned resolutions: %#v", got)
	}
}

func TestResolveDNSNamesIPv4ParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ResolveDNSNamesIPv4(
		ctx,
		[]string{"api.example.com"},
		ResolveUnresolvedOptions{Workers: 1, Timeout: time.Second},
		func(context.Context, string) ([]net.IP, error) {
			t.Fatal("lookup called after cancellation")
			return nil, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestResolveDNSNamesIPv4WithAuditRecordsAllOutcomes(t *testing.T) {
	lookup := func(_ context.Context, name string) ([]net.IP, error) {
		switch name {
		case "resolved.example.com":
			return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:db8::1"), net.ParseIP("8.8.8.8")}, nil
		case "no-ipv4.example.com":
			return []net.IP{net.ParseIP("2001:db8::2")}, nil
		case "timeout.example.com":
			return nil, context.DeadlineExceeded
		case "error.example.com":
			return nil, errors.New("resolver failed")
		default:
			t.Fatalf("unexpected lookup for %q", name)
			return nil, nil
		}
	}

	resolutions, records, err := ResolveDNSNamesIPv4WithAudit(
		context.Background(),
		[]string{"resolved.example.com", "RESOLVED.EXAMPLE.COM.", "no-ipv4.example.com", "timeout.example.com", "error.example.com", "host.local"},
		ResolveUnresolvedOptions{Workers: 4, Timeout: time.Second},
		lookup,
	)
	if err != nil {
		t.Fatalf("ResolveDNSNamesIPv4WithAudit() error = %v", err)
	}
	if want := []DNSNameIPv4Resolution{{DNSName: "resolved.example.com", IPv4s: []string{"8.8.8.8"}}}; !reflect.DeepEqual(resolutions, want) {
		t.Fatalf("resolutions = %#v, want %#v", resolutions, want)
	}
	wantRecords := []ActiveResolveAuditRecord{
		{DNSName: "error.example.com", Status: "error", Error: "resolver failed"},
		{DNSName: "host.local", Status: "skipped_invalid"},
		{DNSName: "no-ipv4.example.com", Status: "no_ipv4"},
		{DNSName: "resolved.example.com", Status: "resolved", IPv4s: []string{"8.8.8.8"}},
		{DNSName: "timeout.example.com", Status: "timeout", Error: context.DeadlineExceeded.Error()},
	}
	if !reflect.DeepEqual(records, wantRecords) {
		t.Fatalf("audit records = %#v, want %#v", records, wantRecords)
	}
}

func TestWriteActiveResolveAuditCSVDeterministicAndHeaderOnly(t *testing.T) {
	records := []ActiveResolveAuditRecord{
		{DNSName: "b.example.com", Status: "error", Error: "lookup, failed"},
		{
			DNSName: "a.example.com", Status: "resolved", IPv4s: []string{"1.1.1.1", "8.8.8.8"},
			MatrixIPs: []string{"8.8.8.8"}, MatrixRowsCompleted: 2,
		},
	}
	options := ResolveUnresolvedOptions{Servers: []string{"9.9.9.9", "1.1.1.1"}, Timeout: 12 * time.Second}
	var first, second bytes.Buffer
	if err := WriteActiveResolveAuditCSV(&first, records, options); err != nil {
		t.Fatalf("WriteActiveResolveAuditCSV() error = %v", err)
	}
	if err := WriteActiveResolveAuditCSV(&second, records, options); err != nil {
		t.Fatalf("second WriteActiveResolveAuditCSV() error = %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("active resolve CSV is not deterministic:\n%s\n%s", first.Bytes(), second.Bytes())
	}
	rows, err := csv.NewReader(bytes.NewReader(first.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("read active resolve CSV: %v", err)
	}
	want := [][]string{
		{"dns_name", "status", "configured_resolvers", "timeout_seconds", "ipv4_answers", "matrix_ips", "matrix_rows_completed", "error"},
		{"a.example.com", "resolved", "9.9.9.9;1.1.1.1", "12", "1.1.1.1;8.8.8.8", "8.8.8.8", "2", ""},
		{"b.example.com", "error", "9.9.9.9;1.1.1.1", "12", "", "", "0", "lookup, failed"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("active resolve CSV rows = %#v, want %#v", rows, want)
	}

	var empty bytes.Buffer
	if err := WriteActiveResolveAuditCSV(&empty, nil, options); err != nil {
		t.Fatalf("header-only WriteActiveResolveAuditCSV() error = %v", err)
	}
	emptyRows, err := csv.NewReader(bytes.NewReader(empty.Bytes())).ReadAll()
	if err != nil || len(emptyRows) != 1 {
		t.Fatalf("header-only rows = %#v, error = %v", emptyRows, err)
	}
}
