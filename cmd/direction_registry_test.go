package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/direction"
)

func TestDirectionSQLRolePredicatesAndQualifiedUDP(t *testing.T) {
	d := direction.Document{Endpoints: []direction.Endpoint{{IP: "10.4.100.58", Server: direction.Server{Listeners: []direction.Behavior{{Protocol: "tcp", Port: 1883}, {Protocol: "udp", Port: 6514, Evidence: "syslog"}, {Protocol: "udp", Port: 9000}}}, Probe: direction.Probe{Targets: []direction.Behavior{{Protocol: "tcp", Port: 22}}}}}}
	sql := strings.Join(strings.Fields(flowDirectionCorrectionSQLForDocument("s", d)), " ")
	for _, want := range []string{
		"src_ip = '10.4.100.58' AND src_port IN (1883)",
		"dst_ip = '10.4.100.58' AND dst_port IN (1883)",
		"dst_ip = '10.4.100.58' AND src_port IN (22)",
		"src_ip = '10.4.100.58' AND dst_port IN (22)",
		"src_ip = '10.4.100.58' AND src_port IN (6514)",
		"AND NOT learned_forward_match", "src_port = 53 AND dst_port != 53", "(src_port = 53 OR dst_port = 53) THEN NULL",
		"IF(swap_reason IS NOT NULL, bytes_to_client, bytes_to_srv) AS bytes_to_srv",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(sql, "9000") {
		t.Fatal("unqualified UDP promoted")
	}
	if strings.Index(sql, "udp_dns_response") > strings.Index(sql, "learned_endpoint_reversed") {
		t.Fatal("DNS priority")
	}
}
func TestRegistryCommands(t *testing.T) {
	dir := t.TempDir()
	daily := filepath.Join(dir, "daily.json")
	reg := filepath.Join(dir, "registry.json")
	out := filepath.Join(dir, "output.sql")
	if err := os.WriteFile(daily, []byte(`{"schema_version":1,"endpoints":[{"ip":"10.4.100.58","server":{"listeners":[{"protocol":"udp","port":6514,"evidence":"syslog"}]}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	root := newRootCommand()
	root.SetArgs([]string{"merge-direction-registry", "--net-id", "s", "--account", "a", "--date", "2026-10-10", "--discoveries", daily, "--output", reg})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	root = newRootCommand()
	root.SetArgs([]string{"render-flow-direction-sql", "--net-id", "s", "--account", "a", "--registry", reg, "--output", out})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "src_port IN (6514)") {
		t.Fatalf("%s %v", data, err)
	}
	root = newRootCommand()
	root.SetArgs([]string{"render-flow-direction-sql", "--net-id", "other", "--account", "a", "--registry", reg, "--output", out})
	if root.Execute() == nil {
		t.Fatal("accepted other stream")
	}
}

func TestRegistrySeedIsEffectiveWithYAMLConfig(t *testing.T) {
	configPath := writeApplicationConfig(t, "schema_version: 1\ncommand: dnsextract\ndnsextract:\n  net_id: yaml-net\n")
	var got DNSExtractOptions
	err := executeConfigMode(context.Background(), []string{"--config", configPath, "--read-dir", "/pcaps", "--direction-registry", "/state/registry.json"}, io.Discard, io.Discard, func(_ context.Context, opts DNSExtractOptions) error { got = opts; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.NetID != "yaml-net" || got.DirectionRegistry != "/state/registry.json" {
		t.Fatalf("lost runtime seed: %+v", got)
	}
}
