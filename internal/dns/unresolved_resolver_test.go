package dns

import (
	"context"
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
