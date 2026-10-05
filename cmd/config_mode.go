// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aglants/pcaptool/internal/appconfig"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const configFlagName = "config"

// hasConfigSelector performs only enough raw argument inspection to select
// config mode before Cobra requires a subcommand and its required flags.
func hasConfigSelector(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--config" || strings.HasPrefix(arg, "--config=") {
			return true
		}
	}
	return false
}

func executeConfigMode(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	executor dnsExtractExecutor,
) error {
	configPath, ordinaryArgs, err := extractConfigSelector(args)
	if err != nil {
		return err
	}
	cli, err := validateConfigModeCLI(ctx, ordinaryArgs)
	if err != nil {
		return err
	}
	if cli.helpRequested {
		return writeConfigModeHelp(ctx, stdout, stderr)
	}

	config, err := appconfig.Load(configPath)
	if err != nil {
		return err
	}
	opts, err := dnsExtractOptionsFromConfig(config, cli.readDir)
	if err != nil {
		return err
	}

	if len(cli.ignored) > 0 {
		fmt.Fprintf(stderr, "warning: --config is authoritative; ignored CLI options: %s\n", strings.Join(cli.ignored, ", "))
	}
	return executor(ctx, opts)
}

func writeConfigModeHelp(ctx context.Context, stdout, stderr io.Writer) error {
	cmd := newRootCommandWithExecutor(func(context.Context, DNSExtractOptions) error { return nil })
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"--help"})
	return cmd.ExecuteContext(ctx)
}

func extractConfigSelector(args []string) (string, []string, error) {
	var configPath string
	ordinaryArgs := make([]string, 0, len(args))
	selectors := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			ordinaryArgs = append(ordinaryArgs, args[i:]...)
			break
		}

		switch {
		case arg == "--config":
			selectors++
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--config requires a non-empty path")
			}
			if args[i+1] == "--config" || strings.HasPrefix(args[i+1], "--config=") {
				return "", nil, fmt.Errorf("--config may be specified only once")
			}
			i++
			configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			selectors++
			configPath = strings.TrimPrefix(arg, "--config=")
		default:
			ordinaryArgs = append(ordinaryArgs, arg)
		}
	}

	if selectors == 0 {
		return "", nil, fmt.Errorf("--config is required in config mode")
	}
	if selectors > 1 {
		return "", nil, fmt.Errorf("--config may be specified only once")
	}
	if configPath == "" {
		return "", nil, fmt.Errorf("--config requires a non-empty path")
	}
	return configPath, ordinaryArgs, nil
}

type configModeCLIValues struct {
	readDir       string
	ignored       []string
	helpRequested bool
}

func validateConfigModeCLI(ctx context.Context, args []string) (configModeCLIValues, error) {
	var parsed DNSExtractOptions
	root := newRootCommandWithExecutor(func(_ context.Context, opts DNSExtractOptions) error {
		parsed = opts
		return nil
	})
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	dnsCommand := findCommand(root, "dnsextract")
	if dnsCommand == nil {
		return configModeCLIValues{}, fmt.Errorf("internal error: dnsextract command is not registered")
	}
	dnsCommand.Args = cobra.NoArgs
	clearRequiredAnnotation(root.PersistentFlags().Lookup("net-id"))
	clearRequiredAnnotation(dnsCommand.Flags().Lookup("read-dir"))

	root.SetArgs(append([]string{"dnsextract"}, args...))
	if err := root.ExecuteContext(ctx); err != nil {
		return configModeCLIValues{}, err
	}
	if help := dnsCommand.Flags().Lookup("help"); help != nil && help.Changed {
		return configModeCLIValues{helpRequested: true}, nil
	}
	readDirFlag := dnsCommand.Flags().Lookup("read-dir")
	if readDirFlag == nil || !readDirFlag.Changed {
		return configModeCLIValues{}, fmt.Errorf("--read-dir is required when --config is used")
	}
	if strings.TrimSpace(parsed.ReadDir) == "" {
		return configModeCLIValues{}, fmt.Errorf("--read-dir must be nonempty when --config is used")
	}
	ignoredSet := make(map[string]struct{})
	root.PersistentFlags().Visit(func(flag *pflag.Flag) {
		if !isConfigModeEffectiveFlag(flag.Name) {
			ignoredSet["--"+flag.Name] = struct{}{}
		}
	})
	dnsCommand.Flags().Visit(func(flag *pflag.Flag) {
		if !isConfigModeEffectiveFlag(flag.Name) {
			ignoredSet["--"+flag.Name] = struct{}{}
		}
	})

	ignored := make([]string, 0, len(ignoredSet))
	for name := range ignoredSet {
		ignored = append(ignored, name)
	}
	sort.Strings(ignored)
	return configModeCLIValues{
		readDir: parsed.ReadDir,
		ignored: ignored,
	}, nil
}

func isConfigModeEffectiveFlag(name string) bool {
	return name == configFlagName || name == "help" || name == "no-banner" || name == "read-dir"
}

func clearRequiredAnnotation(flag *pflag.Flag) {
	if flag == nil {
		return
	}
	delete(flag.Annotations, cobra.BashCompOneRequiredFlag)
}

func findCommand(root *cobra.Command, name string) *cobra.Command {
	for _, command := range root.Commands() {
		if command.Name() == name {
			return command
		}
	}
	return nil
}

func dnsExtractOptionsFromConfig(config *appconfig.Config, readDir string) (DNSExtractOptions, error) {
	opts := DefaultDNSExtractOptions()
	values := config.DNSExtract

	setConfigValue(&opts.NetID, values.NetID)
	opts.ReadDir = readDir
	setConfigValue(&opts.Fleet, values.Fleet)
	setConfigValue(&opts.FleetScanWorkers, values.FleetScanWorkers)
	setConfigValue(&opts.OutputRoot, values.OutputRoot)
	setConfigValue(&opts.Format, values.Format)
	setConfigValue(&opts.ExportCSV, values.ExportCSV)
	setConfigValue(&opts.ManifestOut, values.ManifestOut)
	setConfigValue(&opts.ConnectivityShort, values.Short)
	setConfigValue(&opts.Unsorted, values.Unsorted)
	setConfigValue(&opts.Debug, values.Debug)
	setConfigValue(&opts.RadiusIMSI, values.RadiusIMSI)
	setConfigValue(&opts.OnlyTCP, values.OnlyTCP)
	setConfigValue(&opts.EnforcePrivateAsSource, values.EnforcePrivateAsSource)
	setConfigValue(&opts.InferDNSFromConnections, values.InferDNSFromConnections)
	setConfigValue(&opts.AllowPrivateDNSDonation, values.AllowPrivateDNSDonation)
	setConfigValue(&opts.IgnoreNTP, values.IgnoreNTP)
	setConfigValue(&opts.DisableSNI, values.DisableSNI)
	setConfigValue(&opts.DNSIPFile, values.DNSIPFile)
	setConfigValue(&opts.DNSNormalizationRules, values.DNSNormalizationRules)
	setConfigValue(&opts.ExcludePorts, values.ExcludePorts)
	setConfigValue(&opts.FTPControlPorts, values.FTPControlPorts)
	setConfigValue(&opts.FTPPassiveMinPort, values.FTPPassiveMinPort)
	setConfigValue(&opts.ServerSummaryExcludeUDPPorts, values.ServerSummaryExcludeUDPPorts)
	if values.TopologyDNSWindow != nil {
		opts.TopologyDNSWindow = values.TopologyDNSWindow.Duration
	}
	setConfigValue(&opts.ActiveResolve, values.ActiveResolve)
	setConfigValue(&opts.ActiveResolvers, values.ActiveResolvers)
	setConfigValue(&opts.ReverseDNSLookup, values.ReverseDNSLookup)
	setConfigValue(&opts.TLSCertLookup, values.TLSCertLookup)
	setConfigValue(&opts.TLSCertLookupTimeoutSeconds, values.TLSCertLookupTimeout)
	if values.PostHooks != nil {
		opts.PostHooks = append([]string(nil), (*values.PostHooks)...)
	}

	configDir := filepath.Dir(config.Path)
	opts.Fleet = resolveConfigRelativePath(configDir, opts.Fleet)
	opts.DNSIPFile = resolveConfigRelativePath(configDir, opts.DNSIPFile)
	opts.DNSNormalizationRules = resolveConfigRelativePath(configDir, opts.DNSNormalizationRules)
	opts.OutputRoot = resolveConfigRelativePath(configDir, opts.OutputRoot)

	if _, err := validateDNSExtractOptions(opts); err != nil {
		return DNSExtractOptions{}, fmt.Errorf("validate application config %q: %w", config.Path, err)
	}
	return opts, nil
}

func setConfigValue[T any](destination *T, source *T) {
	if source != nil {
		*destination = *source
	}
}

func resolveConfigRelativePath(configDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}
