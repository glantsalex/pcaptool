package cmd

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestDNSExtractCLIFlagContract(t *testing.T) {
	type flagContract struct {
		name       string
		defaultVal string
		valueType  string
		required   bool
	}

	rootFlags := []flagContract{
		{name: "config", defaultVal: "", valueType: "string"},
		{name: "net-id", defaultVal: "", valueType: "string", required: true},
		{name: "output-root", defaultVal: "pcaptool_output", valueType: "string"},
		{name: "enforce-private-as-source", defaultVal: "false", valueType: "bool"},
		{name: "no-banner", defaultVal: "false", valueType: "bool"},
	}
	localFlags := []flagContract{
		{name: "read-dir", defaultVal: "", valueType: "string", required: true},
		{name: "fleet", defaultVal: "", valueType: "string"},
		{name: "fleet-scan-workers", defaultVal: "0", valueType: "int"},
		{name: "format", defaultVal: "table", valueType: "string"},
		{name: "export-csv", defaultVal: "", valueType: "string"},
		{name: "short", defaultVal: "false", valueType: "bool"},
		{name: "radius-imsi", defaultVal: "false", valueType: "bool"},
		{name: "only-tcp", defaultVal: "false", valueType: "bool"},
		{name: "infer-dns-from-connections", defaultVal: "false", valueType: "bool"},
		{name: "allow-private-dns-donation", defaultVal: "false", valueType: "bool"},
		{name: "ignore-ntp", defaultVal: "true", valueType: "bool"},
		{name: "dns-ip-file", defaultVal: "", valueType: "string"},
		{name: "dns-normalization-rules", defaultVal: "", valueType: "string"},
		{name: "exclude-ports", defaultVal: "53", valueType: "string"},
		{name: "ftp-control-ports", defaultVal: "21,990", valueType: "string"},
		{name: "ftp-passive-min-port", defaultVal: "30000", valueType: "string"},
		{name: "server-summary-exclude-udp-ports", defaultVal: "33434-33534", valueType: "string"},
		{name: "active-resolve", defaultVal: "false", valueType: "bool"},
		{name: "active-resolvers", defaultVal: "", valueType: "string"},
		{name: "reverse-dns-lookup", defaultVal: "false", valueType: "bool"},
		{name: "tls-cert-lookup", defaultVal: "false", valueType: "bool"},
		{name: "tls-cert-lookup-timeout", defaultVal: "15", valueType: "int"},
		{name: "disable-sni", defaultVal: "false", valueType: "bool"},
		{name: "unsorted", defaultVal: "false", valueType: "bool"},
		{name: "debug", defaultVal: "false", valueType: "bool"},
		{name: "manifest-out", defaultVal: "", valueType: "string"},
		{name: "post-hook", defaultVal: "[]", valueType: "stringArray"},
		{name: "topology-dns-window", defaultVal: "2m0s", valueType: "duration"},
	}

	assertFlagContract := func(t *testing.T, cmd *cobra.Command, persistent bool, contracts []flagContract) {
		t.Helper()
		flags := cmd.Flags()
		if persistent {
			flags = cmd.PersistentFlags()
		}
		for _, want := range contracts {
			got := flags.Lookup(want.name)
			if got == nil {
				t.Errorf("flag --%s is missing", want.name)
				continue
			}
			if got.DefValue != want.defaultVal || got.Value.Type() != want.valueType {
				t.Errorf("flag --%s default/type = %q/%q, want %q/%q", want.name, got.DefValue, got.Value.Type(), want.defaultVal, want.valueType)
			}
			required := got.Annotations[cobra.BashCompOneRequiredFlag]
			isRequired := len(required) > 0 && required[0] == "true"
			if isRequired != want.required {
				t.Errorf("flag --%s required = %t, want %t", want.name, isRequired, want.required)
			}
		}
	}

	cmd := dnsextractCommandForTest(t)
	assertFlagContract(t, rootCmd, true, rootFlags)
	assertFlagContract(t, cmd, false, localFlags)
}

func TestCurrentCobraCommandLifecycleContract(t *testing.T) {
	if rootCmd.Runnable() {
		t.Fatal("root command is runnable; current CLI requires a subcommand")
	}
	if rootCmd.Version != "" {
		t.Fatalf("root version = %q, want empty (no --version flag)", rootCmd.Version)
	}

	cmd := dnsextractCommandForTest(t)
	if !cmd.Runnable() {
		t.Fatal("dnsextract command is not runnable")
	}
	if cmd.Args != nil {
		t.Fatal("dnsextract has an Args validator; current CLI accepts arbitrary positional arguments")
	}
	if err := cmd.ValidateArgs([]string{"currently-ignored"}); err != nil {
		t.Fatalf("dnsextract positional argument validation = %v, want nil", err)
	}
}

func TestCurrentCobraRequiredFlagsAndHelpContract(t *testing.T) {
	cmd := newRootCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"dnsextract"})

	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("dnsextract without required flags succeeded")
	}
	for _, flagName := range []string{"net-id", "read-dir"} {
		if !strings.Contains(err.Error(), flagName) {
			t.Fatalf("required-flags error %q does not mention %q", err, flagName)
		}
	}

	helpCmd := newRootCommand()
	helpCmd.SetOut(io.Discard)
	helpCmd.SetErr(io.Discard)
	helpCmd.SetArgs([]string{"dnsextract", "--help"})
	if _, err := helpCmd.ExecuteC(); err != nil {
		t.Fatalf("dnsextract --help error = %v; help must bypass required flags", err)
	}
}

func TestNewRootCommandsDoNotShareDNSExtractOptions(t *testing.T) {
	first := newRootCommand()
	second := newRootCommand()

	if err := first.PersistentFlags().Set("net-id", "first-net"); err != nil {
		t.Fatalf("set first --net-id: %v", err)
	}
	firstDNS := findDNSExtractCommand(t, first)
	if err := firstDNS.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set first --format: %v", err)
	}

	if got := second.PersistentFlags().Lookup("net-id").Value.String(); got != "" {
		t.Fatalf("second --net-id = %q after mutating first command, want empty", got)
	}
	secondDNS := findDNSExtractCommand(t, second)
	if got := secondDNS.Flags().Lookup("format").Value.String(); got != "table" {
		t.Fatalf("second --format = %q after mutating first command, want table", got)
	}
}

func TestDNSExtractCLIAdapterPassesParsedOptionsToValidation(t *testing.T) {
	cmd := newRootCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"dnsextract",
		"--net-id", "test-net",
		"--read-dir", "not-read-because-validation-fails-first",
		"--format", "unsupported",
	})

	_, err := cmd.ExecuteC()
	if err == nil || !strings.Contains(err.Error(), `unsupported --format "unsupported"`) {
		t.Fatalf("CLI adapter error = %v, want parsed format to reach shared validation", err)
	}
}

func findDNSExtractCommand(t *testing.T, root *cobra.Command) *cobra.Command {
	t.Helper()
	for _, cmd := range root.Commands() {
		if cmd.Name() == "dnsextract" {
			return cmd
		}
	}
	t.Fatal("dnsextract command not found")
	return nil
}
