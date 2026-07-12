package dns

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSNormalizationRuleRewritesDirectDNSSynack(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, `
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999]
      observed_dns:
        - prod-ef.g2mobility.com
      cname_contains:
        - iot.tcsevplatform.alzp.tgscloud.net
    set:
      normalized_dns: evse.total-ev-charge.com
`)
	in := []TopologyEntry{{
		IssuerIP:      "10.116.194.47",
		DestinationIP: "3.64.65.68",
		DNSName:       "prod-ef.g2mobility.com",
		DNSSource:     "dns+synack",
		Protocol:      "tcp",
		Port:          9999,
		CNAMEChain:    "iot.tcsevplatform.alzp.tgscloud.net",
	}}

	got, audit := ApplyDNSNormalization("404163-1", in, rules)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	row := got[0]
	if row.DNSName != "evse.total-ev-charge.com" || row.DNSSource != "dns+synack+norm" {
		t.Fatalf("normalized row = %#v", row)
	}
	if row.ObservedDNSName != "prod-ef.g2mobility.com" ||
		row.NormalizedDNSName != "evse.total-ev-charge.com" ||
		row.NormalizationRuleID != "dns_normalize_tcsevplatform_evse" {
		t.Fatalf("normalization metadata not preserved: %#v", row)
	}
	if len(audit) != 1 || !audit[0].CNAMERequired || !audit[0].CNAMEMatched {
		t.Fatalf("audit = %#v, want one CNAME-matched record", audit)
	}
}

func TestDNSNormalizationDoesNotRewriteConnInferred(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, minimalDNSNormalizationRuleYAML("prod-ef.g2mobility.com"))
	in := []TopologyEntry{{
		DestinationIP: "3.64.65.68",
		DNSName:       "prod-ef.g2mobility.com",
		DNSSource:     "dns+conn+synack",
		Protocol:      "tcp",
		Port:          9999,
	}}
	got, audit := ApplyDNSNormalization("404163-1", in, rules)
	if len(audit) != 0 {
		t.Fatalf("audit = %#v, want none", audit)
	}
	if got[0].DNSName != in[0].DNSName || got[0].DNSSource != in[0].DNSSource {
		t.Fatalf("row changed unexpectedly: %#v", got[0])
	}
}

func TestDNSNormalizationRequiresPortProtocolAndNetID(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, minimalDNSNormalizationRuleYAML("prod-ef.g2mobility.com"))
	base := TopologyEntry{
		DestinationIP: "3.64.65.68",
		DNSName:       "prod-ef.g2mobility.com",
		DNSSource:     "dns+synack",
		Protocol:      "tcp",
		Port:          9999,
	}
	cases := []struct {
		name  string
		netID string
		row   TopologyEntry
	}{
		{name: "wrong net id", netID: "other", row: base},
		{name: "wrong protocol", netID: "404163-1", row: func() TopologyEntry { r := base; r.Protocol = "udp"; return r }()},
		{name: "wrong port", netID: "404163-1", row: func() TopologyEntry { r := base; r.Port = 80; return r }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, audit := ApplyDNSNormalization(tc.netID, []TopologyEntry{tc.row}, rules)
			if len(audit) != 0 {
				t.Fatalf("audit = %#v, want none", audit)
			}
			if got[0].DNSName != tc.row.DNSName || got[0].DNSSource != tc.row.DNSSource {
				t.Fatalf("row changed unexpectedly: %#v", got[0])
			}
		})
	}
}

func TestDNSNormalizationSupportsMultiplePorts(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, `
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999, 443]
      observed_dns: [prod-ef.g2mobility.com]
    set:
      normalized_dns: evse.total-ev-charge.com
`)
	in := []TopologyEntry{
		{DNSName: "prod-ef.g2mobility.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999},
		{DNSName: "prod-ef.g2mobility.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 443},
		{DNSName: "prod-ef.g2mobility.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 80},
	}
	got, audit := ApplyDNSNormalization("404163-1", in, rules)
	if len(audit) != 2 {
		t.Fatalf("len(audit) = %d, want 2", len(audit))
	}
	if got[0].DNSSource != "dns+synack+norm" || got[1].DNSSource != "dns+synack+norm" {
		t.Fatalf("expected ports 9999 and 443 to normalize: %#v", got)
	}
	if got[2].DNSSource != "dns+synack" {
		t.Fatalf("port 80 changed unexpectedly: %#v", got[2])
	}
}

func TestDNSNormalizationWildcardObservedDNS(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, `
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999]
      observed_dns: ["*.total-ev-charge.com"]
    set:
      normalized_dns: evse.total-ev-charge.com
`)
	got, audit := ApplyDNSNormalization("404163-1", []TopologyEntry{{
		DNSName:   "EVSE-PSA.Total-EV-Charge.Com.",
		DNSSource: "dns+synack",
		Protocol:  "tcp",
		Port:      9999,
	}}, rules)
	if len(audit) != 1 || got[0].DNSName != "evse.total-ev-charge.com" {
		t.Fatalf("wildcard normalization failed: got=%#v audit=%#v", got, audit)
	}
}

func TestDNSNormalizationCNAMEConditionIsOptional(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, minimalDNSNormalizationRuleYAML("prod-ef.g2mobility.com"))
	got, audit := ApplyDNSNormalization("404163-1", []TopologyEntry{{
		DNSName:   "prod-ef.g2mobility.com",
		DNSSource: "dns+synack",
		Protocol:  "tcp",
		Port:      9999,
	}}, rules)
	if len(audit) != 1 || got[0].DNSSource != "dns+synack+norm" {
		t.Fatalf("optional CNAME rule did not normalize: got=%#v audit=%#v", got, audit)
	}
}

func TestDNSNormalizationRequiresCNAMEWhenConfigured(t *testing.T) {
	rules := mustLoadDNSNormalizationRules(t, `
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999]
      observed_dns: [prod-ef.g2mobility.com]
      cname_contains:
        - iot.tcsevplatform.alzp.tgscloud.net
    set:
      normalized_dns: evse.total-ev-charge.com
`)
	matching := TopologyEntry{DNSName: "prod-ef.g2mobility.com", DNSSource: "dns+synack", Protocol: "tcp", Port: 9999, CNAMEChain: "x.iot.tcsevplatform.alzp.tgscloud.net"}
	nonMatching := matching
	nonMatching.CNAMEChain = "other.example.com"
	missing := matching
	missing.CNAMEChain = ""

	got, audit := ApplyDNSNormalization("404163-1", []TopologyEntry{matching, nonMatching, missing}, rules)
	if len(audit) != 1 {
		t.Fatalf("len(audit) = %d, want 1: %#v", len(audit), audit)
	}
	if got[0].DNSSource != "dns+synack+norm" || got[1].DNSSource != "dns+synack" || got[2].DNSSource != "dns+synack" {
		t.Fatalf("unexpected CNAME-gated result: %#v", got)
	}
}

func TestNormalizedDNSSynackCanDonate(t *testing.T) {
	got := CompleteTopologyWithDNSDonation([]TopologyEntry{
		{DestinationIP: "3.64.65.68", DNSName: "evse.total-ev-charge.com", DNSSource: "dns+synack+norm", Protocol: "tcp", Port: 9999},
		{DestinationIP: "3.64.65.68", DNSName: "", DNSSource: "mid-session", Protocol: "tcp", Port: 9999},
	})
	if got[1].DNSName != "evse.total-ev-charge.com" || got[1].DNSSource != "donated+ipport+norm" {
		t.Fatalf("normalized donor did not donate with normalized source: %#v", got[1])
	}
}

func TestWriteDNSNormalizationAuditCSVColumns(t *testing.T) {
	var buf bytes.Buffer
	err := WriteDNSNormalizationAuditCSV(&buf, []DNSNormalizationAudit{{
		NetID: "404163-1", RuleID: "dns_normalize_tcsevplatform_evse", IssuerIP: "10.0.0.1",
		DestinationIP: "3.64.65.68", Protocol: "tcp", Port: 9999,
		ObservedDNS: "prod-ef.g2mobility.com", NormalizedDNS: "evse.total-ev-charge.com",
		OriginalSource: "dns+synack", NormalizedSource: "dns+synack+norm",
		CNAMERequired: true, CNAMEMatched: true, CNAMEChain: []string{"iot.tcsevplatform.alzp.tgscloud.net"},
	}})
	if err != nil {
		t.Fatalf("WriteDNSNormalizationAuditCSV() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "net_id,rule_id,issuer_ip,destination_ip,protocol,port,observed_dns,normalized_dns,original_source,normalized_source,cname_required,cname_matched,cname_chain") {
		t.Fatalf("missing expected header: %s", out)
	}
	if !strings.Contains(out, "404163-1,dns_normalize_tcsevplatform_evse,10.0.0.1,3.64.65.68,tcp,9999,prod-ef.g2mobility.com,evse.total-ev-charge.com,dns+synack,dns+synack+norm,true,true,iot.tcsevplatform.alzp.tgscloud.net") {
		t.Fatalf("missing expected audit row: %s", out)
	}
}

func mustLoadDNSNormalizationRules(t *testing.T, content string) *DNSNormalizationRules {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	rules, err := LoadDNSNormalizationRules(path)
	if err != nil {
		t.Fatalf("LoadDNSNormalizationRules() error = %v", err)
	}
	return rules
}

func minimalDNSNormalizationRuleYAML(observed string) string {
	return `
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999]
      observed_dns: [` + observed + `]
    set:
      normalized_dns: evse.total-ev-charge.com
`
}
