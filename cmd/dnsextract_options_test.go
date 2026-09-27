package cmd

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultDNSExtractOptions(t *testing.T) {
	want := DNSExtractOptions{
		OutputRoot:                   "pcaptool_output",
		Format:                       "table",
		IgnoreNTP:                    true,
		ExcludePorts:                 "53",
		FTPControlPorts:              "21,990",
		FTPPassiveMinPort:            "30000",
		ServerSummaryExcludeUDPPorts: "33434-33534",
		TLSCertLookupTimeoutSeconds:  15,
		TopologyDNSWindow:            2 * time.Minute,
	}
	if got := DefaultDNSExtractOptions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultDNSExtractOptions() = %#v, want %#v", got, want)
	}
}

func TestValidateDNSExtractOptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DNSExtractOptions)
		wantErr string
	}{
		{name: "defaults"},
		{name: "json format", mutate: func(opts *DNSExtractOptions) { opts.Format = "json" }},
		{name: "invalid format", mutate: func(opts *DNSExtractOptions) { opts.Format = "yaml" }, wantErr: "unsupported --format"},
		{name: "negative topology window", mutate: func(opts *DNSExtractOptions) { opts.TopologyDNSWindow = -time.Second }, wantErr: "--topology-dns-window must be >= 0"},
		{name: "short TLS timeout", mutate: func(opts *DNSExtractOptions) { opts.TLSCertLookupTimeoutSeconds = 4 }, wantErr: "--tls-cert-lookup-timeout"},
		{name: "negative fleet workers", mutate: func(opts *DNSExtractOptions) { opts.FleetScanWorkers = -1 }, wantErr: "--fleet-scan-workers"},
		{name: "invalid FTP controls", mutate: func(opts *DNSExtractOptions) { opts.FTPControlPorts = "21," }, wantErr: "--ftp-control-ports"},
		{name: "invalid FTP passive minimum", mutate: func(opts *DNSExtractOptions) { opts.FTPPassiveMinPort = "0" }, wantErr: "--ftp-passive-min-port"},
		{name: "invalid server summary range", mutate: func(opts *DNSExtractOptions) { opts.ServerSummaryExcludeUDPPorts = "200-100" }, wantErr: "--server-summary-exclude-udp-ports"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultDNSExtractOptions()
			if tt.mutate != nil {
				tt.mutate(&opts)
			}
			validated, err := validateDNSExtractOptions(opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateDNSExtractOptions() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDNSExtractOptions() error = %v", err)
			}
			for _, port := range []uint16{21, 990} {
				if _, ok := validated.ftpControlPorts[port]; !ok {
					t.Fatalf("validated FTP controls missing %d: %#v", port, validated.ftpControlPorts)
				}
			}
			if validated.ftpPassiveMinPort != 30000 {
				t.Fatalf("validated FTP passive minimum = %d, want 30000", validated.ftpPassiveMinPort)
			}
			if _, ok := validated.serverSummaryExcludeUDPPorts[33434]; !ok {
				t.Fatalf("validated server-summary exclusions missing range start: %#v", validated.serverSummaryExcludeUDPPorts)
			}
		})
	}
}

func TestExecuteDNSExtractValidatesOptionsWithoutCobra(t *testing.T) {
	opts := DefaultDNSExtractOptions()
	opts.Format = "unsupported"

	err := executeDNSExtract(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "unsupported --format") {
		t.Fatalf("executeDNSExtract() error = %v, want unsupported format", err)
	}
}
