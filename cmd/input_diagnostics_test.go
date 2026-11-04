package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func diagnosticRecords(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid JSON diagnostic: %s: %v", line, err)
		}
		if record["severity"] != "INFO" || record["component"] != "pcaptool" {
			t.Fatal(record)
		}
		records = append(records, record)
	}
	return records
}

func TestReceivedArgumentsPreserveBoundariesAndRedactHooks(t *testing.T) {
	argv := []string{"pcaptool", "--config", "dir with spaces/config.yaml", "--read-dir", "quote\"\npath", "--post-hook", "secret-one", "--post-hook=secret-two"}
	before := append([]string(nil), argv...)
	var b bytes.Buffer
	logReceivedArguments(&b, argv)
	records := diagnosticRecords(t, &b)
	got := records[0]["argv"].([]any)
	if got[2] != argv[2] || got[4] != argv[4] || len(got) != len(argv) || records[0]["cwd"] == "" {
		t.Fatal(records)
	}
	if strings.Contains(b.String(), "secret-") || !reflect.DeepEqual(argv, before) {
		t.Fatal("secret exposed or argv mutated")
	}
}

func TestInputAccessDistinguishesOptionalMissingAndReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data file.txt")
	if err := os.WriteFile(path, []byte("private contents"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path                string
		directory, optional bool
		status              string
	}{
		{path, false, false, "readable"}, {dir, true, false, "readable"},
		{dir, false, false, "wrong_type"}, {path, true, false, "wrong_type"},
		{path + "missing", false, false, "unreadable"}, {path + "missing", false, true, "optional_absent"},
		{"", false, false, "not_configured"},
	} {
		var b bytes.Buffer
		logInputAccess(&b, "test", tc.path, tc.directory, tc.optional)
		r := diagnosticRecords(t, &b)[0]
		if r["status"] != tc.status || r["path"] != tc.path {
			t.Fatal(r)
		}
		if tc.path != "" && !filepath.IsAbs(r["resolved_path"].(string)) {
			t.Fatal(r)
		}
		if strings.Contains(b.String(), "private contents") {
			t.Fatal("file contents logged")
		}
	}
}

func TestConfigDiagnosticsAndEffectiveResolvedPaths(t *testing.T) {
	path := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-stream
  fleet: fleet with spaces.txt
  dns_ip_file: dns.csv
`)
	var b bytes.Buffer
	err := executeConfigMode(context.Background(), []string{"--config", path, "--read-dir", "pcaps"}, io.Discard, &b,
		func(_ context.Context, opts DNSExtractOptions) error { logDNSExtractInputs(&b, opts); return nil })
	if err != nil {
		t.Fatal(err)
	}
	records := diagnosticRecords(t, &b)
	loaded, fleet := false, false
	for _, r := range records {
		if r["role"] == "config" && r["status"] == "loaded" {
			loaded = true
		}
		if r["role"] == "fleet" {
			fleet = r["resolved_path"] == filepath.Join(filepath.Dir(path), "fleet with spaces.txt") && r["status"] == "unreadable"
		}
	}
	if !loaded || !fleet {
		t.Fatal(records)
	}
	b.Reset()
	if err := executeConfigMode(context.Background(), []string{"--config", path + "missing", "--read-dir", "pcaps"}, io.Discard, &b, nil); err == nil {
		t.Fatal("missing config accepted")
	}
	for _, r := range diagnosticRecords(t, &b) {
		if r["status"] == "loaded" {
			t.Fatal("missing config reported loaded")
		}
	}
}

func TestEffectiveOptionsRedactsHooksAndLabelsUnusedRegistry(t *testing.T) {
	opts := DefaultDNSExtractOptions()
	opts.PostHooks = []string{"secret-hook"}
	opts.DirectionRegistry = "unused.json"
	var b bytes.Buffer
	logDNSExtractInputs(&b, opts)
	if strings.Contains(b.String(), "secret-hook") || opts.PostHooks[0] != "secret-hook" {
		t.Fatal("unsafe options logging")
	}
	found := false
	for _, r := range diagnosticRecords(t, &b) {
		if r["role"] == "direction-registry" && r["status"] == "unused_without_fleet" {
			found = true
		}
	}
	if !found {
		t.Fatal("unused registry not identified")
	}
}

func TestExtractionConfirmsActualInputLoads(t *testing.T) {
	dir := t.TempDir()
	captures := filepath.Join(dir, "pcaps")
	if err := os.Mkdir(captures, 0700); err != nil {
		t.Fatal(err)
	}
	writeDNSArtifactTestPCAP(t, filepath.Join(captures, "capture.pcap"))
	opts := DefaultDNSExtractOptions()
	opts.NetID = "diagnostic-stream"
	opts.ReadDir = captures
	opts.OutputRoot = filepath.Join(dir, "output")
	opts.DisableSNI = true
	opts.Fleet = filepath.Join(dir, "fleet.txt")
	opts.DNSIPFile = filepath.Join(dir, "dns.csv")
	opts.DNSNormalizationRules = filepath.Join(dir, "rules.yaml")
	opts.DirectionRegistry = filepath.Join(dir, "registry.json")
	for path, content := range map[string]string{
		opts.Fleet:                 "10.0.0.1\n",
		opts.DNSIPFile:             "example.test,1.2.3.4\n",
		opts.DNSNormalizationRules: "rules: []\n",
		opts.DirectionRegistry:     `{"schema_version":1,"account_id":"a","stream_id":"diagnostic-stream","endpoints":[]}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	capture, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = capture
	t.Cleanup(func() { os.Stderr = original; _ = capture.Close() })
	err = executeDNSExtract(context.Background(), opts)
	os.Stderr = original
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture.Name())
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]bool{}
	discovered := false
	for _, line := range strings.Split(string(data), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil {
			continue
		}
		if record["severity"] != "INFO" {
			t.Fatal(record)
		}
		if record["status"] == "loaded" {
			loaded[record["role"].(string)] = true
		}
		if record["event"] == "capture_discovery" && record["capture_files"] == float64(1) {
			discovered = true
		}
	}
	for _, role := range []string{"fleet", "dns-ip-file-with-optional-overlay", "dns-normalization-rules", "direction-registry"} {
		if !loaded[role] {
			t.Fatalf("missing successful load confirmation for %s: %s", role, data)
		}
	}
	if !discovered {
		t.Fatal("capture discovery count missing")
	}
}
