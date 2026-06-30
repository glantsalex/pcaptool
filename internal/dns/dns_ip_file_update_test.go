package dns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/connectivity"
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

func TestLoadIPToDNSFromFile_DNSIPFormatCanonicalizesEVSEPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-ip.csv")
	if err := os.WriteFile(path, []byte("EVSE.Total-EV-Charge.COM., 63.183.18.177\n"), 0o644); err != nil {
		t.Fatalf("write dns-ip fixture: %v", err)
	}

	got, err := LoadIPToDNSFromFile(path)
	if err != nil {
		t.Fatalf("LoadIPToDNSFromFile: %v", err)
	}
	names := got["63.183.18.177"]
	if len(names) != 1 || names[0] != "evse.total-ev-charge.com" {
		t.Fatalf("loaded names=%#v, want one canonical EVSE name", names)
	}
}

func TestLoadIPToDNSWithTopologyOverlay_MergesStrictDNSIPRows(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "dns-ip.csv")
	overlayPath := filepath.Join(dir, "topology-lab.csv")
	baseData := []byte("Base.Example.COM.,8.8.8.8\nsecond-base.example,8.8.8.8\n7.7.7.7,IP.First.Example.\n")
	overlayData := []byte(strings.Join([]string{
		"# topology overlay",
		"",
		"Overlay.One.Example., 1.1.1.1",
		"later.example,1.1.1.1",
		"must-not-replace-base.example,8.8.8.8",
		"must-not-replace-ip-first.example,7.7.7.7",
		"9.9.9.9,wrong-order.example",
		"whitespace.example 4.4.4.4",
		"ipv6.example,2001:db8::1",
		"extra-column.example,2.2.2.2,ignored",
		"malformed",
		"Overlay.Two.Example, 3.3.3.3",
	}, "\n"))
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}
	if err := os.WriteFile(overlayPath, overlayData, 0o644); err != nil {
		t.Fatalf("write overlay fixture: %v", err)
	}

	got, err := LoadIPToDNSWithTopologyOverlay(basePath, "lab")
	if err != nil {
		t.Fatalf("LoadIPToDNSWithTopologyOverlay: %v", err)
	}

	if names := got["8.8.8.8"]; len(names) != 2 || names[0] != "base.example.com" || names[1] != "second-base.example" {
		t.Fatalf("base mapping was not preserved: %#v", names)
	}
	if names := got["7.7.7.7"]; len(names) != 1 || names[0] != "ip.first.example" {
		t.Fatalf("ip,dns base mapping was not preserved: %#v", names)
	}
	if names := got["1.1.1.1"]; len(names) != 1 || names[0] != "overlay.one.example" {
		t.Fatalf("first valid overlay row did not win: %#v", names)
	}
	if names := got["3.3.3.3"]; len(names) != 1 || names[0] != "overlay.two.example" {
		t.Fatalf("valid overlay row missing or not canonicalized: %#v", names)
	}
	for _, ip := range []string{"9.9.9.9", "4.4.4.4", "2.2.2.2"} {
		if names, exists := got[ip]; exists {
			t.Fatalf("invalid overlay row unexpectedly loaded for %s: %#v", ip, names)
		}
	}

	assertFileContents(t, basePath, baseData)
	assertFileContents(t, overlayPath, overlayData)
}

func TestLoadIPToDNSWithTopologyOverlay_MissingOverlayUsesBase(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "dns-ip.csv")
	if err := os.WriteFile(basePath, []byte("base.example,8.8.4.4\n"), 0o644); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}

	got, err := LoadIPToDNSWithTopologyOverlay(basePath, "missing")
	if err != nil {
		t.Fatalf("missing overlay should be ignored: %v", err)
	}
	if names := got["8.8.4.4"]; len(names) != 1 || names[0] != "base.example" {
		t.Fatalf("base mapping missing: %#v", names)
	}
}

func TestLoadIPToDNSWithTopologyOverlay_ReturnsOverlayScanError(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "dns-ip.csv")
	if err := os.WriteFile(basePath, nil, 0o644); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}
	overlayPath := filepath.Join(dir, "topology-lab.csv")
	if err := os.WriteFile(overlayPath, []byte(strings.Repeat("x", 1024*1024+1)), 0o644); err != nil {
		t.Fatalf("write oversized overlay fixture: %v", err)
	}

	_, err := LoadIPToDNSWithTopologyOverlay(basePath, "lab")
	if err == nil || !strings.Contains(err.Error(), "scan topology overlay") {
		t.Fatalf("expected overlay scan error, got %v", err)
	}
}

func TestLoadIPToDNSWithTopologyOverlay_FeedsCSVMidAttribution(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "dns-ip.csv")
	if err := os.WriteFile(basePath, nil, 0o644); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "topology-lab.csv"),
		[]byte("EVSE.Total-EV-Charge.COM.,63.183.18.177\n"),
		0o644,
	); err != nil {
		t.Fatalf("write overlay fixture: %v", err)
	}

	ipToDNS, err := LoadIPToDNSWithTopologyOverlay(basePath, "lab")
	if err != nil {
		t.Fatalf("LoadIPToDNSWithTopologyOverlay: %v", err)
	}
	edges := []connectivity.Edge{{
		IssuerIP: "10.93.3.28",
		DstIP:    "63.183.18.177",
		Protocol: connectivity.ProtoTCP,
		Port:     443,
	}}
	got := BuildNetworkTopologyMatrixEntriesWithOptions(nil, edges, nil, ipToDNS, DefaultTopologyBuildOptions())
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %#v", len(got), got)
	}
	if got[0].DNSName != "evse.total-ev-charge.com" || got[0].DNSSource != "csv+mid" {
		t.Fatalf("overlay mapping did not produce csv+mid attribution: %#v", got[0])
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

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("file %s changed: got %q, want %q", path, got, want)
	}
}
