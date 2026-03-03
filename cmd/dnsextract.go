// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/pcap"
	"github.com/aglants/pcaptool/internal/radius"
	"github.com/aglants/pcaptool/output"
	"github.com/aglants/pcaptool/progress"
)

var (
	flagReadDir           string
	flagFormat            string
	flagExportCSV         string
	flagConnectivityShort bool
	flagRadiusIMSI        bool
	flagOnlyTCP           bool
	flagIgnoreNTP         bool
	flagExcludePorts      string
	flagDNSIPFile         string
	flagTopologyDNSWindow time.Duration
	flagActiveResolve     bool
	flagActiveResolvers   string
	flagDisableSNI        bool
)

func init() {
	cmd := &cobra.Command{
		Use:   "dnsextract",
		Short: "Extract DNS A-type queries and correlate responses + connections",
		RunE:  runDNSExtract,
	}

	cmd.Flags().StringVarP(&flagReadDir, "read-dir", "r", "", "Directory containing .pcap files")
	cmd.Flags().StringVar(&flagFormat, "format", "table", "Output format: table|json")
	cmd.Flags().StringVar(&flagExportCSV, "export-csv", "", "Optional CSV export path (relative paths are placed under the run output directory)")
	cmd.Flags().BoolVarP(&flagConnectivityShort, "short", "s", false,
		"write a short connectivity matrix (one row per issuer/DNS/port, ignoring multiple IPs)")
	cmd.Flags().BoolVar(&flagRadiusIMSI, "radius-imsi", false,
		"map issuer IPs to IMSI using RADIUS Accounting records")
	cmd.Flags().BoolVar(&flagOnlyTCP, "only-tcp", false,
		"only consider TCP connections when correlating DNS")
	cmd.Flags().BoolVar(
		&flagIgnoreNTP,
		"ignore-ntp",
		true,
		"Ignore NTP-related DNS names (heuristic: ntp/time/timesync patterns). Set --ignore-ntp=false to keep them.",
	)
	cmd.Flags().StringVar(
		&flagDNSIPFile,
		"dns-ip-file",
		"",
		"CSV file containing DNS,IP pairs used as last-resort IP->DNS attribution (e.g. dns,ip). IPv4 only.",
	)
	cmd.Flags().StringVar(
		&flagExcludePorts,
		"exclude-ports",
		"53",
		"Comma-separated server/destination ports to exclude from network topology matrix (e.g. 53,123). Default: 53",
	)
	cmd.Flags().BoolVar(
		&flagActiveResolve,
		"active-resolve",
		false,
		"Actively resolve unresolved DNS names via external resolvers (disabled by default for forensic stability)",
	)
	cmd.Flags().StringVar(
		&flagActiveResolvers,
		"active-resolvers",
		"",
		"Comma-separated resolver IPs for --active-resolve (e.g. 8.8.8.8,1.1.1.1). Defaults are used when empty.",
	)
	cmd.Flags().BoolVar(
		&flagDisableSNI,
		"disable-sni",
		false,
		"Disable TLS SNI extraction in pass 2 (speeds up truncated/offline workloads by skipping TCP ClientHello scan).",
	)
	cmd.Flags().DurationVar(
		&flagTopologyDNSWindow,
		"topology-dns-window",
		dns.DefaultTopologyBuildOptions().MaxDNSAge,
		"Max age between DNS query and first observed edge for topology DNS attribution (e.g. 30s, 2m). Use 0 to disable time limit.",
	)
	_ = cmd.MarkFlagRequired("read-dir")

	// NOTE: --net-id is now a *persistent* required flag on rootCmd (see root.go).
	// Do NOT mark it required here.

	rootCmd.AddCommand(cmd)
}

func runDNSExtract(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	runStartedAt := time.Now().UTC()

	if flagFormat != "table" && flagFormat != "json" {
		return fmt.Errorf("unsupported --format %q (use table|json)", flagFormat)
	}
	if flagTopologyDNSWindow < 0 {
		return fmt.Errorf("--topology-dns-window must be >= 0")
	}

	om, err := NewOutputManager(flagNetID, flagOutputRoot)
	if err != nil {
		return err
	}

	progress.SetStage("Discovering PCAP files...")
	files, err := pcap.DiscoverPCAPFiles(flagReadDir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .pcap files found in %q", flagReadDir)
	}

	// --------------------------------------------------------------------
	// Pass 1: RADIUS index (if required )
	// --------------------------------------------------------------------
	var imsiIndex *radius.IMSIIndex // adjust type name to your actual exported type
	if flagRadiusIMSI {
		progress.SetStage("Pass 1: building RADIUS IP→IMSI index...")
		idx, err := radius.BuildIMSIIndexFromPCAPs(ctx, files)
		if err != nil {
			return err
		}
		imsiIndex = idx
	}

	// --------------------------------------------------------------------
	// Pass 2: DNS + TLS SNI in one corpus scan (extractors)
	// --------------------------------------------------------------------
	if flagDisableSNI {
		progress.SetStage("Pass 2: scanning DNS (SNI disabled)...")
	} else {
		progress.SetStage("Pass 2: scanning DNS + TLS SNI...")
	}
	txs, _, err := dns.BuildTransactionsWithSNIFromPCAPs(ctx, files, !flagDisableSNI)
	if err != nil {
		return err
	}
	if flagIgnoreNTP {
		progress.SetStage("Pass 2.1: filtering NTP-related DNS transactions...")
		var dropped int
		txs, dropped = dns.FilterOutNTPDNSTransactions(txs)
		progress.SetStage(fmt.Sprintf("Pass 2.1: filtered %d NTP-related DNS transactions.", dropped))
	}

	// --------------------------------------------------------------------
	// Pass 2.5: resolve unresolved DNS names and inject IPv4 results
	// --------------------------------------------------------------------
	if flagActiveResolve {
		progress.SetStage("Pass 2.5: resolving unresolved DNS names (IPv4 only)...")

		opt := dns.DefaultResolveUnresolvedOptions()
		if strings.TrimSpace(flagActiveResolvers) != "" {
			servers, err := parseResolverServers(flagActiveResolvers)
			if err != nil {
				return fmt.Errorf("--active-resolvers: %w", err)
			}
			opt.Servers = servers
		}
		txs, _, err = dns.ResolveUnresolvedDNSTransactions(ctx, txs, opt)
		if err != nil {
			return err
		}
	} else {
		progress.SetStage("Pass 2.5: active resolve disabled; keeping unresolved DNS as-is...")
	}

	// --------------------------------------------------------------------
	// Pass 3: correlate connections (DNS-derived txs only)
	// --------------------------------------------------------------------
	progress.SetStage("Pass 3: correlating connections...")
	excludeSet, err := parsePortSet(flagExcludePorts)
	if err != nil {
		return fmt.Errorf("--exclude-ports: %w", err)
	}
	edges, firstPktInfo, err := dns.AttachConnectionsAndCollectEdgesFromPCAPs(ctx, files, txs, flagOnlyTCP, excludeSet, flagEnforcePrivateAsSource)
	if err != nil {
		return err
	}

	// --------------------------------------------------------------------
	// Identity mapping: default issuer label = IP, optional RADIUS IMSI
	// --------------------------------------------------------------------
	for _, tx := range txs {
		if tx.IssuerIP != nil {
			tx.IssuerLabel = tx.IssuerIP.String()
		} else {
			tx.IssuerLabel = ""
		}
	}

	if flagRadiusIMSI && imsiIndex != nil {
		progress.SetStage("Mapping issuer IPs to IMSI...")
		for _, tx := range txs {
			if tx.IssuerIP == nil {
				continue
			}
			if imsi, ok := imsiIndex.Lookup(tx.IssuerIP, tx.RequestTime); ok && imsi != "" {
				tx.IssuerLabel = imsi
			}
		}
	}

	progress.SetStage("Preparing records for output...")

	// All DNS transactions (with & without connections)
	allRecords := dns.ToOutputRecords(txs)

	// Keep all rows (with & without connections), dedup by (issuer,dns,port)
	// Port will be empty when there was no matched connection.
	records := dns.FilterAndDedupRecords(allRecords)
	dns.SortOutputRecords(records)

	progress.SetStage(fmt.Sprintf("Writing output to %s...", om.RunDir()))

	// ---------------------------
	// Main output
	// ---------------------------
	var mainName string
	if flagFormat == "json" {
		mainName = "dns-table.json"
	} else {
		mainName = "dns-table.txt"
	}

	mainOut, err := om.Create(mainName)
	if err != nil {
		return err
	}
	defer mainOut.Close()

	switch flagFormat {
	case "table":
		stats := dns.ComputeTableStatsFromTx(txs, records)
		if err := output.WriteTableWithStats(mainOut, records, stats); err != nil {
			return err
		}

		// NOTE: Unused-DNS report intentionally disabled (was causing OOM in some datasets).
		// TODO: if will be re-enabled  later, make it bounded/streamed and write it here under OutputManager.

	case "json":
		if err := output.WriteJSON(mainOut, records); err != nil {
			return err
		}
	}

	// ---------------------------
	// Extra report: per-issuer DNS profile
	// ---------------------------
	issuerProf := dns.ComputeIssuerProfile(txs)
	if len(issuerProf) > 0 {
		pf, err := om.Create("dns-issuer-profile.txt")
		if err != nil {
			return fmt.Errorf("create dns issuer profile: %w", err)
		}
		defer pf.Close()

		if err := output.WriteIssuerProfileTable(pf, issuerProf); err != nil {
			return fmt.Errorf("write dns issuer profile: %w", err)
		}
	}

	// ---------------------------
	// Extra report: network topology matrix (issuer → dstIP → DNSName? → proto → port)
	// ---------------------------
	issuerFn := func(ip string, ts time.Time) string {
		// Default: use IP
		if !flagRadiusIMSI || imsiIndex == nil {
			return ip
		}
		// Conservative mapping: use time-aware lookup
		if imsi, ok := imsiIndex.Lookup(net.ParseIP(ip), ts); ok && imsi != "" {
			return imsi
		}
		return ip
	}
	var ipToDNS map[string][]string
	if strings.TrimSpace(flagDNSIPFile) != "" {
		m, err := dns.LoadIPToDNSFromFile(flagDNSIPFile)
		if err != nil {
			return fmt.Errorf("load --dns-ip-file: %w", err)
		}

		learned := dns.StrongObservedIPDNSPairsFromTransactions(txs)
		merged, newPairs := dns.MergeIPToDNSMaps(m, learned)
		if len(newPairs) > 0 {
			if err := dns.AppendIPDNSPairsToFile(flagDNSIPFile, newPairs); err != nil {
				return fmt.Errorf("append learned IP->DNS pairs to %q: %w", flagDNSIPFile, err)
			}
		}
		ipToDNS = merged
	}

	topoOpt := dns.DefaultTopologyBuildOptions()
	topoOpt.MaxDNSAge = flagTopologyDNSWindow
	topo := dns.BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, issuerFn, ipToDNS, topoOpt)
	if flagConnectivityShort {
		topo = dns.SquashNetworkTopologyShort(topo)
	}
	if len(topo) > 0 {
		mf, err := om.Create("network-topology-matrix.txt")
		if err != nil {
			return fmt.Errorf("create network topology matrix: %w", err)
		}
		defer mf.Close()

		if err := output.WriteNetworkTopologyMatrix(mf, topo); err != nil {
			return fmt.Errorf("write network topology matrix: %w", err)
		}
	}

	// ---------------------------
	// Extra report: service endpoints JSON
	// Unique tuples: (public destination IP, DNS name, port)
	// ---------------------------
	serviceEndpoints := dns.BuildServiceEndpoints(topo)
	sef, err := om.Create("service-endpoints.txt")
	if err != nil {
		return fmt.Errorf("create service-endpoints.txt: %w", err)
	}
	defer sef.Close()

	if err := output.WriteServiceEndpointsJSON(sef, serviceEndpoints); err != nil {
		return fmt.Errorf("write service-endpoints.txt: %w", err)
	}

	// ---------------------------
	// Extra report: unresolved DNS (post-topology attribution)
	// ---------------------------
	unresolvedFinal := dns.ComputeUnresolvedDNSFirstSeen(txs)
	unresolvedFinal = dns.FilterUnresolvedByTopologyAttribution(unresolvedFinal, topo)
	if len(unresolvedFinal) > 0 {
		uf, err := om.Create("dns-unresolved-dns.txt")
		if err != nil {
			return fmt.Errorf("create unresolved dns report: %w", err)
		}
		defer uf.Close()

		if err := output.WriteUnresolvedDNSTable(uf, unresolvedFinal); err != nil {
			return fmt.Errorf("write unresolved dns report: %w", err)
		}
	}

	// ---------------------------
	// Extra report: external endpoints (grouped by dns_suffix)
	// Derived from network topology matrix entries
	// ---------------------------
	if len(topo) > 0 {
		endpoints := dns.BuildExternalEndpoints(topo)
		if len(endpoints) > 0 {
			ef, err := om.Create("external-endpoints.txt")
			if err != nil {
				return fmt.Errorf("create external-endpoints.txt: %w", err)
			}
			defer ef.Close()

			if err := dns.WriteExternalEndpoints(ef, endpoints); err != nil {
				return fmt.Errorf("write external-endpoints.txt: %w", err)
			}
		}
	}

	// ---------------------------
	// Optional CSV export (same rows as records)
	// ---------------------------
	if flagExportCSV != "" {
		csvPath := om.ResolvePath(flagExportCSV)

		// If ResolvePath returned a relative-under-run-dir path, ensure parent dirs exist.
		// For absolute paths, we still create parents if missing.
		if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
			return fmt.Errorf("create csv parent dir for %q: %w", csvPath, err)
		}

		if err := output.WriteCSV(csvPath, records); err != nil {
			return err
		}
	}

	// ---------------------------
	// Extra report: unresolved public destination IPs (no DNS attribution)
	// ---------------------------
	unresolvedIPs := dns.PublicUnresolvedDestinationIPs(topo)
	if len(unresolvedIPs) > 0 {
		uf, err := om.Create("unresolved-ip.txt")
		if err != nil {
			return fmt.Errorf("create unresolved-ip.txt: %w", err)
		}
		defer uf.Close()

		for _, ip := range unresolvedIPs {
			if _, err := fmt.Fprintln(uf, ip); err != nil {
				return fmt.Errorf("write unresolved-ip.txt: %w", err)
			}
		}
	}
	if err := writeRunMetadata(om, runStartedAt, flagReadDir, len(files), firstPktInfo); err != nil {
		return fmt.Errorf("write run-metadata.txt: %w", err)
	}

	progress.Done("Completed dnsextract successfully.")
	return nil
}

func writeRunMetadata(
	om *OutputManager,
	runStartedAt time.Time,
	readDir string,
	pcapFilesCount int,
	first dns.FirstPacketInfo,
) error {
	f, err := om.Create("_run-metadata.txt")
	if err != nil {
		return err
	}
	defer f.Close()

	firstTS := ""
	if !first.Timestamp.IsZero() {
		firstTS = first.Timestamp.UTC().Format(time.RFC3339Nano)
	}

	if _, err := fmt.Fprintf(
		f,
		"run_id: %s\nnet_id: %s\nrun_started_at_utc: %s\nread_dir: %s\npcap_files_count: %d\nfirst_packet_ts_utc: %s\nfirst_packet_pcap_file: %s\n",
		om.RunID(),
		om.NetID(),
		runStartedAt.UTC().Format(time.RFC3339Nano),
		filepath.Clean(readDir),
		pcapFilesCount,
		firstTS,
		first.PCAPFile,
	); err != nil {
		return err
	}
	return nil
}

func parseResolverServers(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)

	for p := range strings.SplitSeq(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("invalid resolver IP %q", p)
		}
		canon := ip.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid resolver IPs provided")
	}
	return out, nil
}
