package dns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrongObservedIPDNSPairsFromTransactions(t *testing.T) {
	txStrong := &DNSTransaction{
		DNSName:     "Api.Example.COM.",
		ResolvedIPs: mustIPs(t, "34.120.10.1"),
		ResolvedIPEvidence: map[string]Evidence{
			"34.120.10.1": EvDNSAnswer | EvObservedConn,
		},
	}
	txStrongConn := &DNSTransaction{
		DNSName:     "api.example.com",
		ResolvedIPs: mustIPs(t, "34.120.10.2"),
		ResolvedIPEvidence: map[string]Evidence{
			"34.120.10.2": EvDNSAnswer | EvConnInferred | EvObservedConn,
		},
	}
	txWeakNoObserved := &DNSTransaction{
		DNSName:     "weak.example.com",
		ResolvedIPs: mustIPs(t, "34.120.10.3"),
		ResolvedIPEvidence: map[string]Evidence{
			"34.120.10.3": EvDNSAnswer,
		},
	}
	txWeakSNI := &DNSTransaction{
		DNSName:      "sni.example.com",
		NameEvidence: EvSNI,
		ResolvedIPs:  mustIPs(t, "34.120.10.4"),
		ResolvedIPEvidence: map[string]Evidence{
			"34.120.10.4": EvSNI | EvObservedConn,
		},
	}
	txPrivate := &DNSTransaction{
		DNSName:     "private.example.com",
		ResolvedIPs: mustIPs(t, "10.10.10.10"),
		ResolvedIPEvidence: map[string]Evidence{
			"10.10.10.10": EvDNSAnswer | EvObservedConn,
		},
	}

	got := StrongObservedIPDNSPairsFromTransactions([]*DNSTransaction{
		txStrong,
		txStrongConn,
		txWeakNoObserved,
		txWeakSNI,
		txPrivate,
	})

	if len(got["34.120.10.1"]) != 1 || got["34.120.10.1"][0] != "api.example.com" {
		t.Fatalf("expected strong dns+synack pair for 34.120.10.1, got %#v", got["34.120.10.1"])
	}
	if _, ok := got["34.120.10.2"]; ok {
		t.Fatalf("unexpected conn-inferred pair 34.120.10.2 present: %#v", got["34.120.10.2"])
	}
	if _, ok := got["34.120.10.3"]; ok {
		t.Fatalf("unexpected weak pair 34.120.10.3 present: %#v", got["34.120.10.3"])
	}
	if _, ok := got["34.120.10.4"]; ok {
		t.Fatalf("unexpected sni-only pair 34.120.10.4 present: %#v", got["34.120.10.4"])
	}
	if _, ok := got["10.10.10.10"]; ok {
		t.Fatalf("unexpected private pair present: %#v", got["10.10.10.10"])
	}
}

func TestMergeIPToDNSMaps_ReturnsOnlyNewPairs(t *testing.T) {
	base := map[string][]string{
		"34.120.10.1": {"api.example.com"},
	}
	extra := map[string][]string{
		"34.120.10.1": {"api.example.com", "alt.example.com"},
		"34.120.10.2": {"new.example.com", "very-long.subdomain.new.example.com"},
	}

	merged, newPairs := MergeIPToDNSMaps(base, extra)
	if len(merged["34.120.10.1"]) != 1 || merged["34.120.10.1"][0] != "api.example.com" {
		t.Fatalf("expected existing IP to stay unchanged, got %#v", merged["34.120.10.1"])
	}
	if len(merged["34.120.10.2"]) != 1 || merged["34.120.10.2"][0] != "new.example.com" {
		t.Fatalf("expected single deterministic name for 34.120.10.2, got %#v", merged["34.120.10.2"])
	}
	if len(newPairs) != 1 {
		t.Fatalf("expected only unseen-IP pair to be new, got %#v", newPairs)
	}
	if newPairs[0].IP != "34.120.10.2" || newPairs[0].DNS != "new.example.com" {
		t.Fatalf("unexpected new pair %#v", newPairs[0])
	}
}

func TestAppendIPDNSPairsToFile_AppendsNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip-dns.txt")

	initial := "existing.example.com,34.120.10.1"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial file: %v", err)
	}

	pairs := []IPDNSPair{
		{DNS: "new.example.com", IP: "34.120.10.2"},
		{DNS: "alt.example.com", IP: "34.120.10.1"},
	}
	if err := AppendIPDNSPairsToFile(path, pairs); err != nil {
		t.Fatalf("append pairs: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "existing.example.com,34.120.10.1") {
		t.Fatalf("missing existing pair, got:\n%s", text)
	}
	if !strings.Contains(text, "new.example.com,34.120.10.2") {
		t.Fatalf("missing new pair, got:\n%s", text)
	}
	if !strings.Contains(text, "alt.example.com,34.120.10.1") {
		t.Fatalf("missing second new pair, got:\n%s", text)
	}
}

func mustIPs(t *testing.T, values ...string) []net.IP {
	t.Helper()
	out := make([]net.IP, 0, len(values))
	for _, v := range values {
		ip := net.ParseIP(v)
		if ip == nil {
			t.Fatalf("invalid test IP %q", v)
		}
		out = append(out, ip)
	}
	return out
}
