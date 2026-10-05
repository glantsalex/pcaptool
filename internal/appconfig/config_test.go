// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package appconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalConfig = `schema_version: 1
command: dnsextract
dnsextract:
  net_id: test-net
`

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, minimalConfig+`  fleet_scan_workers: 0
  debug: false
  topology_dns_window: 2m
  post_hooks: []
`)

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Path != path {
		t.Fatalf("Path = %q, want %q", config.Path, path)
	}
	if config.SchemaVersion == nil || *config.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %v, want pointer to 1", config.SchemaVersion)
	}
	if config.Command != "dnsextract" {
		t.Fatalf("Command = %q, want dnsextract", config.Command)
	}
	if config.DNSExtract == nil {
		t.Fatal("DNSExtract = nil")
	}
	if config.DNSExtract.FleetScanWorkers == nil || *config.DNSExtract.FleetScanWorkers != 0 {
		t.Fatalf("FleetScanWorkers = %v, want pointer to 0", config.DNSExtract.FleetScanWorkers)
	}
	if config.DNSExtract.Debug == nil || *config.DNSExtract.Debug {
		t.Fatalf("Debug = %v, want pointer to false", config.DNSExtract.Debug)
	}
	if config.DNSExtract.TopologyDNSWindow == nil || config.DNSExtract.TopologyDNSWindow.Duration != 2*time.Minute {
		t.Fatalf("TopologyDNSWindow = %v, want 2m", config.DNSExtract.TopologyDNSWindow)
	}
	if config.DNSExtract.PostHooks == nil || len(*config.DNSExtract.PostHooks) != 0 {
		t.Fatalf("PostHooks = %v, want pointer to empty slice", config.DNSExtract.PostHooks)
	}
	if config.DNSExtract.Format != nil {
		t.Fatalf("Format = %v, want nil for omitted field", config.DNSExtract.Format)
	}
}

func TestLoadResolvesConfigPathFromWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	absPath := filepath.Join(configDir, "app.yaml")
	if err := os.WriteFile(absPath, []byte(minimalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	config, err := Load(filepath.Join("config", ".", "app.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Path != absPath {
		t.Fatalf("Path = %q, want %q", config.Path, absPath)
	}
}

func TestLoadPreservesAbsoluteConfigPath(t *testing.T) {
	path := writeConfig(t, minimalConfig)
	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Path != path {
		t.Fatalf("Path = %q, want %q", config.Path, path)
	}
}

func TestLoadRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "empty", content: "", want: "empty YAML document"},
		{name: "comments only", content: "# no document\n", want: "empty YAML document"},
		{name: "multiple documents", content: minimalConfig + "---\n" + minimalConfig, want: "multiple YAML documents"},
		{name: "missing schema version", content: "command: dnsextract\ndnsextract:\n  net_id: n\n", want: "schema_version: field is required"},
		{name: "unsupported schema version", content: strings.Replace(minimalConfig, "schema_version: 1", "schema_version: 2", 1), want: "schema_version: unsupported value 2; use 1"},
		{name: "missing command", content: "schema_version: 1\ndnsextract:\n  net_id: n\n", want: "command: field is required"},
		{name: "blank command", content: strings.Replace(minimalConfig, "command: dnsextract", "command: '  '", 1), want: "command: field is required"},
		{name: "unsupported command", content: strings.Replace(minimalConfig, "command: dnsextract", "command: serviceclassify", 1), want: `command: unsupported value "serviceclassify"; use dnsextract`},
		{name: "missing dnsextract", content: "schema_version: 1\ncommand: dnsextract\n", want: `dnsextract: block is required for command "dnsextract"`},
		{name: "null dnsextract", content: "schema_version: 1\ncommand: dnsextract\ndnsextract: null\n", want: `dnsextract: block is required for command "dnsextract"`},
		{name: "missing net id", content: "schema_version: 1\ncommand: dnsextract\ndnsextract: {}\n", want: "dnsextract.net_id: field is required"},
		{name: "blank net id", content: strings.Replace(minimalConfig, "net_id: test-net", "net_id: '  '", 1), want: "dnsextract.net_id: field is required"},
		{name: "read dir is not a YAML field", content: minimalConfig + "  read_dir: ./pcaps\n", want: "field read_dir not found in type appconfig.DNSExtractConfig"},
		{name: "unknown root field", content: minimalConfig + "unknown: true\n", want: "field unknown not found in type appconfig.Config"},
		{name: "unknown nested field", content: minimalConfig + "  unknown: true\n", want: "field unknown not found in type appconfig.DNSExtractConfig"},
		{name: "other command block", content: minimalConfig + "serviceclassify: {}\n", want: "field serviceclassify not found in type appconfig.Config"},
		{name: "invalid duration", content: minimalConfig + "  topology_dns_window: soon\n", want: `invalid Go duration "soon"`},
		{name: "numeric duration", content: minimalConfig + "  topology_dns_window: 120\n", want: "duration must be a string using Go duration syntax"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil")
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("Load() error = %q, want config path %q", err, path)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadRejectsEmptyPath(t *testing.T) {
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "application config path is empty") {
		t.Fatalf("Load() error = %v, want empty path error", err)
	}
}

func TestLoadReadErrorIncludesAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	_, err := Load("missing.yaml")
	if err == nil {
		t.Fatal("Load() error = nil")
	}
	wantPath := filepath.Join(dir, "missing.yaml")
	if !strings.Contains(err.Error(), wantPath) {
		t.Fatalf("Load() error = %q, want path %q", err, wantPath)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
