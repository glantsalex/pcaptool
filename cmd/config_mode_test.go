package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigModeUsesCLIReadDirWithoutSubcommand(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: yaml-net
`)
	const runtimeReadDir = "/runtime/pcaps"

	var got DNSExtractOptions
	called := 0
	err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", runtimeReadDir}, io.Discard, io.Discard,
		func(_ context.Context, opts DNSExtractOptions) error {
			called++
			got = opts
			return nil
		})
	if err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if called != 1 {
		t.Fatalf("executor calls = %d, want 1", called)
	}
	if got.NetID != "yaml-net" {
		t.Fatalf("NetID = %q, want yaml-net", got.NetID)
	}
	if got.ReadDir != runtimeReadDir {
		t.Fatalf("ReadDir = %q, want unchanged CLI value %q", got.ReadDir, runtimeReadDir)
	}
}

func TestConfigModeDoesNotExpandCLIReadDir(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`)

	for _, readDir := range []string{"~/pcaps", "$PCAP_STAGE/pcaps"} {
		t.Run(readDir, func(t *testing.T) {
			var got DNSExtractOptions
			err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", readDir}, io.Discard, io.Discard,
				func(_ context.Context, opts DNSExtractOptions) error {
					got = opts
					return nil
				})
			if err != nil {
				t.Fatalf("executeConfigMode() error = %v", err)
			}
			if got.ReadDir != readDir {
				t.Fatalf("ReadDir = %q, want literal CLI value %q", got.ReadDir, readDir)
			}
		})
	}
}

func TestEquivalentCLIAndYAMLProduceEquivalentOptions(t *testing.T) {
	configDir := t.TempDir()
	readDir := filepath.Join(configDir, "pcaps")
	fleet := filepath.Join(configDir, "fleet.txt")
	outputRoot := filepath.Join(configDir, "output")
	dnsIPFile := filepath.Join(configDir, "dns.csv")
	normalizationRules := filepath.Join(configDir, "normalization.yaml")

	yaml := fmt.Sprintf(`schema_version: 1
command: dnsextract
dnsextract:
  net_id: equivalent-net
  fleet: %q
  fleet_scan_workers: 3
  output_root: %q
  format: json
  export_csv: export.csv
  manifest_out: manifest.json
  short: true
  unsorted: true
  debug: true
  radius_imsi: true
  only_tcp: true
  enforce_private_as_source: true
  infer_dns_from_connections: true
  allow_private_dns_donation: true
  ignore_ntp: false
  disable_sni: true
  dns_ip_file: %q
  dns_normalization_rules: %q
  exclude_ports: "53,123"
  ftp_control_ports: "21,990"
  ftp_passive_min_port: "31000"
  server_summary_exclude_udp_ports: "33434-33534"
  topology_dns_window: 45s
  active_resolve: true
  active_resolvers: "8.8.8.8"
  reverse_dns_lookup: true
  tls_cert_lookup: true
  tls_cert_lookup_timeout: 20
  post_hooks:
    - first hook
    - second hook
`, fleet, outputRoot, dnsIPFile, normalizationRules)
	configPath := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	var cliOptions DNSExtractOptions
	cli := newRootCommandWithExecutor(func(_ context.Context, opts DNSExtractOptions) error {
		cliOptions = opts
		return nil
	})
	cli.SilenceErrors = true
	cli.SilenceUsage = true
	cli.SetOut(io.Discard)
	cli.SetErr(io.Discard)
	cli.SetArgs([]string{
		"dnsextract",
		"--net-id", "equivalent-net",
		"--read-dir", readDir,
		"--fleet", fleet,
		"--fleet-scan-workers", "3",
		"--output-root", outputRoot,
		"--format", "json",
		"--export-csv", "export.csv",
		"--manifest-out", "manifest.json",
		"--short", "--unsorted", "--debug", "--radius-imsi", "--only-tcp",
		"--enforce-private-as-source", "--infer-dns-from-connections",
		"--allow-private-dns-donation", "--ignore-ntp=false", "--disable-sni",
		"--dns-ip-file", dnsIPFile,
		"--dns-normalization-rules", normalizationRules,
		"--exclude-ports", "53,123",
		"--ftp-control-ports", "21,990",
		"--ftp-passive-min-port", "31000",
		"--server-summary-exclude-udp-ports", "33434-33534",
		"--topology-dns-window", "45s",
		"--active-resolve", "--active-resolvers", "8.8.8.8",
		"--reverse-dns-lookup", "--tls-cert-lookup", "--tls-cert-lookup-timeout", "20",
		"--post-hook", "first hook", "--post-hook", "second hook",
	})
	if err := cli.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("CLI ExecuteContext() error = %v", err)
	}

	var yamlOptions DNSExtractOptions
	if err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", readDir}, io.Discard, io.Discard,
		func(_ context.Context, opts DNSExtractOptions) error {
			yamlOptions = opts
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}

	if !reflect.DeepEqual(yamlOptions, cliOptions) {
		t.Fatalf("YAML options differ from CLI options:\nYAML: %#v\n CLI: %#v", yamlOptions, cliOptions)
	}
}

func TestConfigModeUsesSharedDNSExtractDefaults(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: defaults-net
`)
	const runtimeReadDir = "relative/runtime-pcaps"

	var got DNSExtractOptions
	if err := executeConfigMode(context.Background(), []string{"--config", configPath, "-r", runtimeReadDir}, io.Discard, io.Discard,
		func(_ context.Context, opts DNSExtractOptions) error {
			got = opts
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}

	want := DefaultDNSExtractOptions()
	want.NetID = "defaults-net"
	want.ReadDir = runtimeReadDir
	want.OutputRoot = filepath.Join(filepath.Dir(configPath), want.OutputRoot)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config defaults = %#v, want shared defaults %#v", got, want)
	}
}

func TestConfigModeIgnoresRecognizedCLIOptionsAndWarnsDeterministically(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: yaml-net
  debug: false
  format: table
`)

	var stderr bytes.Buffer
	var got DNSExtractOptions
	err := executeConfigMode(context.Background(), []string{
		"--config", configPath,
		"-r", "/stage/run42",
		"--net-id", "WRONG",
		"--format", "json",
		"--debug",
		"--no-banner",
	}, io.Discard, &stderr, func(_ context.Context, opts DNSExtractOptions) error {
		got = opts
		return nil
	})
	if err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if got.NetID != "yaml-net" || got.ReadDir != "/stage/run42" || got.Format != "table" || got.Debug {
		t.Fatalf("CLI values leaked into config options: %#v", got)
	}
	const wantWarning = "warning: --config is authoritative; ignored CLI options: --debug, --format, --net-id\n"
	if stderr.String() != wantWarning {
		t.Fatalf("stderr = %q, want %q", stderr.String(), wantWarning)
	}
}

func TestConfigModePathResolution(t *testing.T) {
	workingDir := t.TempDir()
	configDir := filepath.Join(workingDir, "configs")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "app.yaml")
	config := `schema_version: 1
command: dnsextract
dnsextract:
  net_id: paths-net
  fleet: ./fleet.txt
  dns_ip_file: ~/dns.csv
  dns_normalization_rules: $PCAPTOOL_RULES/rules.yaml
  output_root: ./output/../runs
  export_csv: relative-export.csv
  manifest_out: relative-manifest.json
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workingDir)

	var got DNSExtractOptions
	const runtimeReadDir = "./runtime/../pcaps"
	if err := executeConfigMode(context.Background(), []string{"-r", runtimeReadDir, "--config", "configs/app.yaml"}, io.Discard, io.Discard,
		func(_ context.Context, opts DNSExtractOptions) error {
			got = opts
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}

	checks := map[string]struct {
		got  string
		want string
	}{
		"read_dir":                {got.ReadDir, runtimeReadDir},
		"fleet":                   {got.Fleet, filepath.Join(configDir, "fleet.txt")},
		"dns_ip_file":             {got.DNSIPFile, filepath.Join(configDir, "~", "dns.csv")},
		"dns_normalization_rules": {got.DNSNormalizationRules, filepath.Join(configDir, "$PCAPTOOL_RULES", "rules.yaml")},
		"output_root":             {got.OutputRoot, filepath.Join(configDir, "runs")},
		"export_csv":              {got.ExportCSV, "relative-export.csv"},
		"manifest_out":            {got.ManifestOut, "relative-manifest.json"},
	}
	for name, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q", name, check.got, check.want)
		}
	}
}

func TestConfigModeRejectsInvalidCLIEnvelope(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"--config", configPath, "--read-dir", "/pcaps", "--not-a-flag"}, want: "unknown flag"},
		{name: "malformed bool", args: []string{"--config", configPath, "--read-dir", "/pcaps", "--debug=maybe"}, want: "invalid argument"},
		{name: "malformed int", args: []string{"--config", configPath, "--read-dir", "/pcaps", "--fleet-scan-workers=nope"}, want: "invalid argument"},
		{name: "malformed duration", args: []string{"--config", configPath, "--read-dir", "/pcaps", "--topology-dns-window=nope"}, want: "invalid argument"},
		{name: "positional argument", args: []string{"--config", configPath, "--read-dir", "/pcaps", "extra"}, want: "unknown command"},
		{name: "explicit subcommand", args: []string{"dnsextract", "--config", configPath, "--read-dir", "/pcaps"}, want: "unknown command"},
		{name: "missing read dir", args: []string{"--config", configPath}, want: "--read-dir is required when --config is used"},
		{name: "empty read dir", args: []string{"--config", configPath, "--read-dir="}, want: "--read-dir must be nonempty"},
		{name: "empty short read dir", args: []string{"--config", configPath, "-r", ""}, want: "--read-dir must be nonempty"},
		{name: "duplicate selectors", args: []string{"--config", configPath, "--read-dir", "/pcaps", "--config=" + configPath}, want: "only once"},
		{name: "adjacent duplicate selectors", args: []string{"--config", "--config=" + configPath}, want: "only once"},
		{name: "empty equals selector", args: []string{"--config="}, want: "non-empty path"},
		{name: "empty separate selector", args: []string{"--config", ""}, want: "non-empty path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			err := executeConfigMode(context.Background(), tt.args, io.Discard, io.Discard,
				func(context.Context, DNSExtractOptions) error {
					called = true
					return nil
				})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("executeConfigMode() error = %v, want substring %q", err, tt.want)
			}
			if called {
				t.Fatal("executor called for invalid config-mode arguments")
			}
		})
	}
}

func TestConfigModeHelpDoesNotLoadConfigOrExecute(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	var stdout bytes.Buffer
	called := false
	err := executeConfigMode(context.Background(), []string{"--config", missingPath, "--help"}, &stdout, io.Discard,
		func(context.Context, DNSExtractOptions) error {
			called = true
			return nil
		})
	if err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if called {
		t.Fatal("executor called while showing config-mode help")
	}
	if output := stdout.String(); !strings.Contains(output, "Usage:") || !strings.Contains(output, "--config") {
		t.Fatalf("help output = %q, want root usage with --config", output)
	}
}

func TestConfigModeDoesNotTreatFlagValueAsHelp(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`)
	var stderr bytes.Buffer
	called := false
	err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", "/pcaps", "--post-hook", "-h"}, io.Discard, &stderr,
		func(context.Context, DNSExtractOptions) error {
			called = true
			return nil
		})
	if err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if !called {
		t.Fatal("executor was not called; -h used as a flag value was treated as help")
	}
	if !strings.Contains(stderr.String(), "--post-hook") {
		t.Fatalf("stderr = %q, want ignored --post-hook warning", stderr.String())
	}
}

func TestConfigModeNoBannerRemainsProcessOnly(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`)
	args := []string{"--config", configPath, "--read-dir", "/pcaps", "--no-banner"}
	if !SuppressBannerFromArgs(args) {
		t.Fatal("SuppressBannerFromArgs() = false, want true")
	}
	var stderr bytes.Buffer
	called := false
	if err := executeConfigMode(context.Background(), args, io.Discard, &stderr,
		func(context.Context, DNSExtractOptions) error {
			called = true
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if !called {
		t.Fatal("executor was not called")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no ignored-option warning", stderr.String())
	}
}

func TestConfigModeExecutesDNSExtractWithCaptureFixture(t *testing.T) {
	configDir := t.TempDir()
	readDir := filepath.Join(configDir, "pcaps")
	if err := os.Mkdir(readDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDNSArtifactTestPCAP(t, filepath.Join(readDir, "capture.pcap"))
	configPath := filepath.Join(configDir, "config.yaml")
	config := `schema_version: 1
command: dnsextract
dnsextract:
  net_id: config-integration
  output_root: ./output
  disable_sni: true
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", readDir}, io.Discard, io.Discard, executeDNSExtract); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	runDir := findSingleRunDir(t, filepath.Join(configDir, "output"), "config-integration")
	if _, err := os.Stat(filepath.Join(runDir, "_run-artifacts.json")); err != nil {
		t.Fatalf("stat generated manifest: %v", err)
	}
}

func TestExtractConfigSelectorRejectsMissingPath(t *testing.T) {
	_, _, err := extractConfigSelector([]string{"--config"})
	if err == nil || !strings.Contains(err.Error(), "non-empty path") {
		t.Fatalf("extractConfigSelector() error = %v, want non-empty path error", err)
	}
}

func TestConfigDurationUsesSharedSemanticValidation(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
  topology_dns_window: -1s
`)
	err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", "/pcaps"}, io.Discard, io.Discard,
		func(context.Context, DNSExtractOptions) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "--topology-dns-window must be >= 0") {
		t.Fatalf("executeConfigMode() error = %v, want shared semantic validation error", err)
	}
}

func TestConfigModePreservesExplicitZeroValues(t *testing.T) {
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
  fleet_scan_workers: 0
  topology_dns_window: 0s
  post_hooks: []
`)
	var got DNSExtractOptions
	if err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", "/pcaps"}, io.Discard, io.Discard,
		func(_ context.Context, opts DNSExtractOptions) error {
			got = opts
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
	if got.FleetScanWorkers != 0 || got.TopologyDNSWindow != 0 || len(got.PostHooks) != 0 {
		t.Fatalf("explicit zero values not preserved: %#v", got)
	}
}

func TestHasConfigSelectorStopsAtDoubleDash(t *testing.T) {
	if hasConfigSelector([]string{"--", "--config", "file.yaml"}) {
		t.Fatal("hasConfigSelector() treated a positional token after -- as a selector")
	}
}

func TestConfigModeExecutorReceivesContext(t *testing.T) {
	type contextKey string
	const key contextKey = "test"
	ctx := context.WithValue(context.Background(), key, "value")
	configPath := writeApplicationConfig(t, `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`)
	if err := executeConfigMode(ctx, []string{"--config", configPath, "--read-dir", "/pcaps"}, io.Discard, io.Discard,
		func(got context.Context, _ DNSExtractOptions) error {
			if got.Value(key) != "value" {
				t.Fatal("executor did not receive config-mode context")
			}
			return nil
		}); err != nil {
		t.Fatalf("executeConfigMode() error = %v", err)
	}
}

func writeApplicationConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
