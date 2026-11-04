package cmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aglants/pcaptool/internal/direction"
)

const (
	flowDirectionCorrectionSQLFilename = "flow-direction-correction.sql"
	flowDirectionCorrectionSQLKey      = "flow_direction_correction_sql"
	directionSQLLineWidth              = 100
)

type directionSide uint8

const (
	directionSource directionSide = iota
	directionDestination
)

func (s directionSide) mirror() directionSide { return 1 - s }
func (s directionSide) column(suffix string) string {
	if s == directionSource {
		return "src_" + suffix
	}
	return "dst_" + suffix
}

// IP and port selectors are independent: a reversed probe matches dst_ip but
// src_port (the target service on the fleet device). Never flatten this to IP:port.
type directionRule struct {
	protocol string
	ipSide   directionSide
	ip       string
	portSide directionSide
	port     uint16
}

func (r directionRule) mirror() directionRule {
	r.ipSide = r.ipSide.mirror()
	r.portSide = r.portSide.mirror()
	return r
}

type directionRuleKey struct {
	protocol string
	ipSide   directionSide
	ip       string
	portSide directionSide
}
type directionRuleGroup struct {
	key   directionRuleKey
	ports []uint16
}

func (g directionRuleGroup) mirror() directionRuleGroup {
	g.key.ipSide = g.key.ipSide.mirror()
	g.key.portSide = g.key.portSide.mirror()
	return g
}

// directionRules derives one canonical reversal collection. Daily artifacts may
// carry unqualified UDP observations; only positive syslog evidence is admitted.
// Registry learning, evidence dates and stored representation are not changed.
func directionRules(d direction.Document) []directionRule {
	var rules []directionRule
	for _, e := range d.Endpoints {
		for _, b := range e.Server.Listeners {
			if b.Protocol == "udp" && b.Evidence != "syslog" {
				continue
			}
			rules = append(rules, directionRule{b.Protocol, directionSource, e.IP, directionSource, b.Port})
		}
		for _, b := range e.Probe.Targets {
			if b.Protocol != "tcp" {
				continue
			}
			rules = append(rules, directionRule{b.Protocol, directionDestination, e.IP, directionSource, b.Port})
		}
	}
	return rules
}

// Ordering is protocol, IP side (source first), literal IP string, port side,
// then numeric port. Forward groups retain this order after mechanical mirroring.
// The OR alternatives share one reason, so their ordering is not policy priority.
func groupDirectionRules(rules []directionRule) []directionRuleGroup {
	byKey := make(map[directionRuleKey]map[uint16]struct{})
	for _, r := range rules {
		key := directionRuleKey{r.protocol, r.ipSide, r.ip, r.portSide}
		if byKey[key] == nil {
			byKey[key] = make(map[uint16]struct{})
		}
		byKey[key][r.port] = struct{}{}
	}
	groups := make([]directionRuleGroup, 0, len(byKey))
	for key, ports := range byKey {
		group := directionRuleGroup{key: key}
		for p := range ports {
			group.ports = append(group.ports, p)
		}
		sort.Slice(group.ports, func(i, j int) bool { return group.ports[i] < group.ports[j] })
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i].key, groups[j].key
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		if a.ipSide != b.ipSide {
			return a.ipSide < b.ipSide
		}
		if a.ip != b.ip {
			return a.ip < b.ip
		}
		return a.portSide < b.portSide
	})
	return groups
}

var directionBaseColumns = []string{
	"device_id", "start_time", "end_time", "src_ip", "dst_ip", "src_port", "dst_port",
	"bytes_to_srv", "bytes_to_client", "pckt_to_srv", "pckt_to_client", "protocol_lc",
}

// flowDirectionCorrectionSQLForDocument is the shared daily/cumulative renderer.
// Parsed expressions are named once for readability, not a guarantee of physical
// evaluation count. Scalar predicates preserve SQL TRUE/FALSE/NULL behavior.
func flowDirectionCorrectionSQLForDocument(netID string, d direction.Document) string {
	groups := groupDirectionRules(directionRules(d))
	byProtocol := make(map[string][]directionRuleGroup)
	var protocols []string
	for _, g := range groups {
		if len(byProtocol[g.key.protocol]) == 0 {
			protocols = append(protocols, g.key.protocol)
		}
		byProtocol[g.key.protocol] = append(byProtocol[g.key.protocol], g)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "-- direction-generator: %s\n", direction.GeneratorVersion)
	b.WriteString("-- Rendering: grouped scalar rules; cumulative evidence and policies are unchanged.\n")
	b.WriteString("CREATE OR REPLACE MATERIALIZED VIEW\n")
	fmt.Fprintf(&b, "  `{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-%s`\n", netID)
	b.WriteString("PARTITION BY TIMESTAMP_TRUNC(start_time, HOUR)\nAS\nWITH parsed AS (\n  SELECT\n")
	for _, c := range directionBaseColumns {
		if c == "protocol_lc" {
			c = "LOWER(protocol) AS protocol_lc"
		}
		fmt.Fprintf(&b, "    %s,\n", c)
	}
	b.WriteString("    NET.SAFE_IP_FROM_STRING(src_ip) AS src_ip_bytes,\n")
	b.WriteString("    NET.SAFE_IP_FROM_STRING(dst_ip) AS dst_ip_bytes\n")
	fmt.Fprintf(&b, "  FROM `{{gcp_project_id}}.{{bq_dataset}}.flow-data-%s`\n", netID)
	b.WriteString("),\nbase AS (\n  SELECT\n")
	writeDirectionColumns(&b, directionBaseColumns, true)
	writeDirectionPrivatePredicate(&b, "src")
	b.WriteString(",\n")
	writeDirectionPrivatePredicate(&b, "dst")
	b.WriteString("\n  FROM parsed\n),\nlearned AS (\n  SELECT\n")
	writeDirectionColumns(&b, appendDirectionColumns("src_is_private", "dst_is_private"), true)
	b.WriteString("    -- Mirroring exchanges both selectors; NULL matches remain NULL.\n")
	if len(protocols) == 0 {
		b.WriteString("    FALSE AS learned_reverse_match,\n    FALSE AS learned_forward_match\n")
	}
	for i, p := range protocols {
		reverse, forward := directionMatchNames(i, p)
		fmt.Fprintf(&b, "    -- %s endpoint evidence.\n", p)
		writeDirectionMatch(&b, byProtocol[p], false, reverse)
		b.WriteString(",\n")
		writeDirectionMatch(&b, byProtocol[p], true, forward)
		if i < len(protocols)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  FROM base\n),\ndecide AS (\n  SELECT\n")
	writeDirectionColumns(&b, directionBaseColumns, true)
	b.WriteString("    CASE\n")
	b.WriteString("      -- Priority: outside-to-private, DNS, then unambiguous learned direction.\n")
	b.WriteString("      WHEN NOT src_is_private\n        AND dst_is_private\n        THEN 'public_to_private_artifact'\n")
	b.WriteString("      WHEN src_is_private AND dst_is_private\n        AND protocol_lc = 'udp'\n        AND src_port = 53\n        AND dst_port != 53\n        THEN 'udp_dns_response'\n")
	if len(byProtocol["udp"]) > 0 {
		b.WriteString("      -- DNS preservation must precede learned syslog UDP correction.\n")
		b.WriteString("      WHEN src_is_private AND dst_is_private\n        AND protocol_lc = 'udp'\n        AND (src_port = 53 OR dst_port = 53)\n        THEN NULL\n")
	}
	for i, p := range protocols {
		reverse, forward := directionMatchNames(i, p)
		b.WriteString("      -- A forward match suppresses reversal, including conflicting endpoint roles.\n")
		fmt.Fprintf(&b, "      WHEN src_is_private AND dst_is_private\n        AND protocol_lc = %s\n        AND %s\n        AND NOT %s\n        THEN 'learned_endpoint_reversed'\n", sqlStringLiteral(p), reverse, forward)
	}
	b.WriteString("      ELSE NULL\n    END AS swap_reason\n  FROM learned\n)\nSELECT\n")
	b.WriteString("  device_id,\n  start_time,\n  end_time,\n")
	for _, pair := range [][2]string{{"src_ip", "dst_ip"}, {"src_port", "dst_port"}} {
		writeDirectionSwap(&b, pair)
	}
	b.WriteString("  protocol_lc AS protocol,\n")
	writeDirectionSwap(&b, [2]string{"bytes_to_srv", "bytes_to_client"})
	// The final column has no trailing comma.
	b.WriteString("  IF(swap_reason IS NOT NULL, pckt_to_client, pckt_to_srv) AS pckt_to_srv,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, pckt_to_srv, pckt_to_client) AS pckt_to_client\nFROM decide;\n")
	return b.String()
}

func directionMatchNames(index int, protocol string) (string, string) {
	suffix := ""
	if protocol == "udp" {
		suffix = "_udp"
	} else if index > 0 {
		suffix = "_" + strconv.Itoa(index+1)
	}
	return "learned_reverse_match" + suffix, "learned_forward_match" + suffix
}
func appendDirectionColumns(extra ...string) []string {
	return append(append([]string{}, directionBaseColumns...), extra...)
}
func writeDirectionColumns(b *strings.Builder, columns []string, trailing bool) {
	for i, c := range columns {
		fmt.Fprintf(b, "    %s", c)
		if trailing || i < len(columns)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
}
func writeDirectionPrivatePredicate(b *strings.Builder, side string) {
	fmt.Fprintf(b, `    COALESCE(
      (
        NET.IP_TRUNC(%[1]s_ip_bytes, 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(%[1]s_ip_bytes, 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(%[1]s_ip_bytes, 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(%[1]s_ip_bytes, 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    ) AS %[1]s_is_private`, side)
}
func writeDirectionMatch(b *strings.Builder, groups []directionRuleGroup, mirror bool, name string) {
	b.WriteString("    (\n")
	for i, g := range groups {
		if mirror {
			g = g.mirror()
		}
		if i == 0 {
			b.WriteString("      (\n")
		} else {
			b.WriteString("      OR (\n")
		}
		fmt.Fprintf(b, "        %s = %s\n", g.key.ipSide.column("ip"), sqlStringLiteral(g.key.ip))
		prefix := "        AND " + g.key.portSide.column("port") + " IN ("
		parts := make([]string, len(g.ports))
		for i, p := range g.ports {
			parts[i] = strconv.Itoa(int(p))
		}
		joined := strings.Join(parts, ", ")
		if len(prefix)+len(joined)+1 <= directionSQLLineWidth {
			b.WriteString(prefix + joined + ")\n")
		} else {
			b.WriteString(prefix + "\n")
			line := "          "
			for i, p := range parts {
				token := p
				if i < len(parts)-1 {
					token += ","
				}
				if len(line)+len(token) > directionSQLLineWidth {
					b.WriteString(strings.TrimRight(line, " ") + "\n")
					line = "          "
				}
				line += token + " "
			}
			b.WriteString(strings.TrimRight(line, " ") + "\n        )\n")
		}
		b.WriteString("      )\n")
	}
	fmt.Fprintf(b, "    ) AS %s", name)
}
func writeDirectionSwap(b *strings.Builder, pair [2]string) {
	fmt.Fprintf(b, "  IF(swap_reason IS NOT NULL, %s, %s) AS %s,\n", pair[1], pair[0], pair[0])
	fmt.Fprintf(b, "  IF(swap_reason IS NOT NULL, %s, %s) AS %s,\n", pair[0], pair[1], pair[1])
}
func sqlStringLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
