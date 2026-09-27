package cmd

import (
	"fmt"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
)

// DNSExtractOptions contains the source-neutral configuration for one
// dnsextract execution. CLI parsing is responsible only for populating this
// model; execution and semantic validation do not depend on Cobra.
type DNSExtractOptions struct {
	NetID                        string
	OutputRoot                   string
	EnforcePrivateAsSource       bool
	ReadDir                      string
	Fleet                        string
	FleetScanWorkers             int
	Format                       string
	ExportCSV                    string
	ConnectivityShort            bool
	RadiusIMSI                   bool
	OnlyTCP                      bool
	InferDNSFromConnections      bool
	AllowPrivateDNSDonation      bool
	IgnoreNTP                    bool
	DNSIPFile                    string
	DNSNormalizationRules        string
	ExcludePorts                 string
	FTPControlPorts              string
	FTPPassiveMinPort            string
	ServerSummaryExcludeUDPPorts string
	ActiveResolve                bool
	ActiveResolvers              string
	ReverseDNSLookup             bool
	TLSCertLookup                bool
	TLSCertLookupTimeoutSeconds  int
	DisableSNI                   bool
	Unsorted                     bool
	Debug                        bool
	ManifestOut                  string
	PostHooks                    []string
	TopologyDNSWindow            time.Duration
}

// DefaultDNSExtractOptions returns the defaults shared by all dnsextract
// configuration sources.
func DefaultDNSExtractOptions() DNSExtractOptions {
	return DNSExtractOptions{
		OutputRoot:                   "pcaptool_output",
		Format:                       "table",
		IgnoreNTP:                    true,
		ExcludePorts:                 "53",
		FTPControlPorts:              "21,990",
		FTPPassiveMinPort:            "30000",
		ServerSummaryExcludeUDPPorts: "33434-33534",
		TLSCertLookupTimeoutSeconds:  15,
		TopologyDNSWindow:            dns.DefaultTopologyBuildOptions().MaxDNSAge,
	}
}

type validatedDNSExtractOptions struct {
	ftpControlPorts              map[uint16]struct{}
	ftpPassiveMinPort            uint16
	serverSummaryExcludeUDPPorts map[uint16]struct{}
}

func validateDNSExtractOptions(opts DNSExtractOptions) (validatedDNSExtractOptions, error) {
	if opts.Format != "table" && opts.Format != "json" {
		return validatedDNSExtractOptions{}, fmt.Errorf("unsupported --format %q (use table|json)", opts.Format)
	}
	if opts.TopologyDNSWindow < 0 {
		return validatedDNSExtractOptions{}, fmt.Errorf("--topology-dns-window must be >= 0")
	}
	if err := validateTLSCertLookupTimeout(opts.TLSCertLookupTimeoutSeconds); err != nil {
		return validatedDNSExtractOptions{}, err
	}
	if err := validateFleetScanWorkers(opts.Fleet, opts.FleetScanWorkers); err != nil {
		return validatedDNSExtractOptions{}, err
	}
	ftpControlPorts, err := parseStrictPortSet(opts.FTPControlPorts)
	if err != nil {
		return validatedDNSExtractOptions{}, fmt.Errorf("--ftp-control-ports: %w", err)
	}
	ftpPassiveMinPort, err := parseStrictPort(opts.FTPPassiveMinPort)
	if err != nil {
		return validatedDNSExtractOptions{}, fmt.Errorf("--ftp-passive-min-port: %w", err)
	}
	serverSummaryExcludeUDPPorts, err := parseOptionalPortRangeSet(opts.ServerSummaryExcludeUDPPorts)
	if err != nil {
		return validatedDNSExtractOptions{}, fmt.Errorf("--server-summary-exclude-udp-ports: %w", err)
	}

	return validatedDNSExtractOptions{
		ftpControlPorts:              ftpControlPorts,
		ftpPassiveMinPort:            ftpPassiveMinPort,
		serverSummaryExcludeUDPPorts: serverSummaryExcludeUDPPorts,
	}, nil
}

func validateFleetScanWorkers(_ string, workers int) error {
	if workers < 0 {
		return fmt.Errorf("--fleet-scan-workers must be >= 0")
	}
	return nil
}

func validateTLSCertLookupTimeout(seconds int) error {
	if seconds < 5 || seconds > 30 {
		return fmt.Errorf("--tls-cert-lookup-timeout must be an integer from 5 to 30 seconds (got %d)", seconds)
	}
	return nil
}
