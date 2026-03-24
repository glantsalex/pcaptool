// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// flagNetID is a global network identifier used to scope all output artifacts.
// It is a persistent flag on the root command so that all subcommands share
// the same output directory convention.
var flagNetID string
var flagOutputRoot string

var flagEnforcePrivateAsSource bool
var flagNoBanner bool

var rootCmd = &cobra.Command{
	Use:   "pcaptool",
	Short: "High-performance PCAP analysis toolkit",
	Long:  "pcaptool is a modular, high-performance CLI for extracting insights from PCAP files.",
}

// Execute runs the root command.
func Execute() {
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

func init() {
	rootCmd.PersistentFlags().StringVar(
		&flagNetID,
		"net-id",
		"",
		"Network identifier (required). Used as <output-root>/<net-id>/<run-id>",
	)
	rootCmd.PersistentFlags().StringVarP(
		&flagOutputRoot,
		"output-root",
		"o",
		"pcaptool_output",
		"Root directory for all outputs. Per-run layout: <output-root>/<net-id>/<run-id>",
	)
	rootCmd.PersistentFlags().BoolVar(
		&flagEnforcePrivateAsSource,
		"enforce-private-as-source",
		false,
		"For UDP only: if one side is private/local, always treat it as the source (swap direction when needed)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&flagNoBanner,
		"no-banner",
		false,
		"Suppress the startup banner",
	)

	if err := rootCmd.MarkPersistentFlagRequired("net-id"); err != nil {
		// Only fails if the flag is missing — programmer error.
		panic(fmt.Errorf("mark --net-id as required: %w", err))
	}
}
