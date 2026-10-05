// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package appconfig loads the versioned application configuration file.
package appconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const schemaVersion uint32 = 1

// Config is the schema-versioned application configuration document.
// Path is the clean, absolute path from which the document was loaded.
type Config struct {
	Path          string            `yaml:"-"`
	SchemaVersion *uint32           `yaml:"schema_version"`
	Command       string            `yaml:"command"`
	DNSExtract    *DNSExtractConfig `yaml:"dnsextract"`
}

// DNSExtractConfig contains explicitly configured dnsextract values. Pointer
// fields preserve the distinction between an omitted value and an explicit
// zero value so the command layer can apply its shared defaults.
type DNSExtractConfig struct {
	NetID                        *string   `yaml:"net_id"`
	Fleet                        *string   `yaml:"fleet"`
	FleetScanWorkers             *int      `yaml:"fleet_scan_workers"`
	OutputRoot                   *string   `yaml:"output_root"`
	Format                       *string   `yaml:"format"`
	ExportCSV                    *string   `yaml:"export_csv"`
	ManifestOut                  *string   `yaml:"manifest_out"`
	Short                        *bool     `yaml:"short"`
	Unsorted                     *bool     `yaml:"unsorted"`
	Debug                        *bool     `yaml:"debug"`
	RadiusIMSI                   *bool     `yaml:"radius_imsi"`
	OnlyTCP                      *bool     `yaml:"only_tcp"`
	EnforcePrivateAsSource       *bool     `yaml:"enforce_private_as_source"`
	InferDNSFromConnections      *bool     `yaml:"infer_dns_from_connections"`
	AllowPrivateDNSDonation      *bool     `yaml:"allow_private_dns_donation"`
	IgnoreNTP                    *bool     `yaml:"ignore_ntp"`
	DisableSNI                   *bool     `yaml:"disable_sni"`
	DNSIPFile                    *string   `yaml:"dns_ip_file"`
	DNSNormalizationRules        *string   `yaml:"dns_normalization_rules"`
	ExcludePorts                 *string   `yaml:"exclude_ports"`
	FTPControlPorts              *string   `yaml:"ftp_control_ports"`
	FTPPassiveMinPort            *string   `yaml:"ftp_passive_min_port"`
	ServerSummaryExcludeUDPPorts *string   `yaml:"server_summary_exclude_udp_ports"`
	TopologyDNSWindow            *Duration `yaml:"topology_dns_window"`
	ActiveResolve                *bool     `yaml:"active_resolve"`
	ActiveResolvers              *string   `yaml:"active_resolvers"`
	ReverseDNSLookup             *bool     `yaml:"reverse_dns_lookup"`
	TLSCertLookup                *bool     `yaml:"tls_cert_lookup"`
	TLSCertLookupTimeout         *int      `yaml:"tls_cert_lookup_timeout"`
	PostHooks                    *[]string `yaml:"post_hooks"`
}

// Duration is a YAML duration encoded using Go duration syntax, such as 2m or
// 500ms.
type Duration struct {
	time.Duration
}

// UnmarshalYAML decodes a duration from a YAML string scalar.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("duration must be a string using Go duration syntax")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid Go duration %q: %w", node.Value, err)
	}
	d.Duration = parsed
	return nil
}

// Load reads, strictly decodes, and validates one application configuration
// document. Relative paths are resolved against the process working directory;
// symlinks are not evaluated.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("application config path is empty")
	}

	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("resolve application config path %q: %w", path, err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read application config %q: %w", absPath, err)
	}

	config := &Config{Path: absPath}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("parse application config %q: empty YAML document", absPath)
		}
		return nil, fmt.Errorf("parse application config %q: %w", absPath, err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse application config %q: %w", absPath, err)
		}
		return nil, fmt.Errorf("parse application config %q: multiple YAML documents are not supported", absPath)
	}

	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("validate application config %q: %w", absPath, err)
	}
	return config, nil
}

func (c *Config) validate() error {
	if c.SchemaVersion == nil {
		return fmt.Errorf("schema_version: field is required")
	}
	if *c.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version: unsupported value %d; use %d", *c.SchemaVersion, schemaVersion)
	}
	if strings.TrimSpace(c.Command) == "" {
		return fmt.Errorf("command: field is required")
	}
	if c.Command != "dnsextract" {
		return fmt.Errorf("command: unsupported value %q; use dnsextract", c.Command)
	}
	if c.DNSExtract == nil {
		return fmt.Errorf("dnsextract: block is required for command %q", c.Command)
	}
	if c.DNSExtract.NetID == nil || strings.TrimSpace(*c.DNSExtract.NetID) == "" {
		return fmt.Errorf("dnsextract.net_id: field is required")
	}
	return nil
}
