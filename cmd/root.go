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
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = newRootCommand()

// Execute runs the root command.
func Execute() {
	if hasConfigSelector(os.Args[1:]) {
		if err := executeConfigMode(context.Background(), os.Args[1:], os.Stdout, os.Stderr, executeDNSExtract); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SuppressBannerFromArgs reports whether the raw CLI args request suppressing
// the startup banner before Cobra parses flags.
func SuppressBannerFromArgs(args []string) bool {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		switch {
		case arg == "--no-banner":
			return true
		case strings.HasPrefix(arg, "--no-banner="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--no-banner="))
			return value == "" || value == "true" || value == "1"
		}
	}
	return false
}

func newRootCommand() *cobra.Command {
	return newRootCommandWithExecutor(executeDNSExtract)
}

func newRootCommandWithExecutor(executor dnsExtractExecutor) *cobra.Command {
	opts := DefaultDNSExtractOptions()
	cmd := &cobra.Command{
		Use:   "pcaptool",
		Short: "High-performance PCAP analysis toolkit",
		Long:  "pcaptool is a modular, high-performance CLI for extracting insights from PCAP files.",
	}

	cmd.PersistentFlags().StringVar(
		&opts.NetID,
		"net-id",
		opts.NetID,
		"Network identifier (required). Used as <output-root>/<net-id>/pcap-date-<date>/run-<UTC>",
	)
	cmd.PersistentFlags().StringVarP(
		&opts.OutputRoot,
		"output-root",
		"o",
		opts.OutputRoot,
		"Root directory for all outputs. Layout: <output-root>/<net-id>/pcap-date-<date>/run-<UTC>",
	)
	cmd.PersistentFlags().BoolVar(
		&opts.EnforcePrivateAsSource,
		"enforce-private-as-source",
		opts.EnforcePrivateAsSource,
		"For UDP only: if one side is private/local, always treat it as the source (swap direction when needed)",
	)
	var noBanner bool
	cmd.PersistentFlags().BoolVar(
		&noBanner,
		"no-banner",
		false,
		"Suppress the startup banner",
	)
	var configPath string
	cmd.PersistentFlags().StringVar(
		&configPath,
		"config",
		"",
		"Run the command selected by a YAML application configuration file",
	)

	if err := cmd.MarkPersistentFlagRequired("net-id"); err != nil {
		// Only fails if the flag is missing — programmer error.
		panic(fmt.Errorf("mark --net-id as required: %w", err))
	}

	cmd.AddCommand(newDNSExtractCommandWithExecutor(&opts, executor))
	return cmd
}
