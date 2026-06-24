package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/aglants/pcaptool/internal/syntrail"
)

const (
	flowDirectionCorrectionSQLFilename = "flow-direction-correction.sql"
	flowDirectionCorrectionSQLKey      = "flow_direction_correction_sql"
)

func writeFlowDirectionCorrectionSQL(om *OutputManager, tuples []syntrail.ServerTuple) (string, error) {
	f, err := om.Create(flowDirectionCorrectionSQLFilename)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", flowDirectionCorrectionSQLFilename, err)
	}

	path := f.Name()
	writeErr := writeFlowDirectionCorrectionSQLContent(f, om.NetID(), tuples)
	closeErr := f.Close()
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", flowDirectionCorrectionSQLFilename, writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", flowDirectionCorrectionSQLFilename, closeErr)
	}

	return path, nil
}

func writeFlowDirectionCorrectionSQLContent(w io.Writer, netID string, tuples []syntrail.ServerTuple) error {
	_, err := fmt.Fprint(w, flowDirectionCorrectionSQL(netID, tuples))
	return err
}

func flowDirectionCorrectionSQL(netID string, tuples []syntrail.ServerTuple) string {
	sourceTable := fmt.Sprintf("`{{gcp_project_id}}.{{bq_dataset}}.flow-data-%s`", netID)
	targetView := fmt.Sprintf("`{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-%s`", netID)

	var b strings.Builder
	fmt.Fprintf(&b, "CREATE OR REPLACE MATERIALIZED VIEW %s\n", targetView)
	b.WriteString("PARTITION BY TIMESTAMP_TRUNC(start_time, HOUR)\n")
	b.WriteString("AS\n")
	b.WriteString("WITH base AS (\n")
	b.WriteString("  SELECT\n")
	b.WriteString("    device_id, start_time, end_time,\n")
	b.WriteString("    src_ip, dst_ip, src_port, dst_port,\n")
	b.WriteString("    bytes_to_srv, bytes_to_client,\n")
	b.WriteString("    pckt_to_srv, pckt_to_client,\n")
	b.WriteString("    LOWER(protocol) AS protocol_lc,\n")
	b.WriteString("    (\n")
	b.WriteString("      REGEXP_CONTAINS(src_ip, r'^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)')\n")
	b.WriteString("      OR STARTS_WITH(src_ip, '100.104.')\n")
	b.WriteString("    ) AS src_is_private,\n")
	b.WriteString("    (\n")
	b.WriteString("      REGEXP_CONTAINS(dst_ip, r'^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)')\n")
	b.WriteString("      OR STARTS_WITH(dst_ip, '100.104.')\n")
	b.WriteString("    ) AS dst_is_private\n")
	fmt.Fprintf(&b, "  FROM %s\n", sourceTable)
	b.WriteString("),\n")
	b.WriteString("decide AS (\n")
	b.WriteString("  SELECT\n")
	b.WriteString("    *,\n")
	b.WriteString("    CASE\n")
	b.WriteString("      WHEN (NOT src_is_private) AND dst_is_private\n")
	b.WriteString("        THEN 'public_to_private_artifact'\n")
	for _, tuple := range tuples {
		protocol := string(tuple.Protocol)
		fmt.Fprintf(&b, "      WHEN src_is_private\n")
		b.WriteString("       AND dst_is_private\n")
		fmt.Fprintf(&b, "       AND protocol_lc = %s\n", sqlStringLiteral(protocol))
		fmt.Fprintf(&b, "       AND src_ip = %s\n", sqlStringLiteral(tuple.DstIP.String()))
		fmt.Fprintf(&b, "       AND src_port = %d\n", tuple.DstPort)
		fmt.Fprintf(&b, "        THEN %s\n", sqlStringLiteral(privateServerSwapReason(tuple)))
	}
	b.WriteString("      ELSE NULL\n")
	b.WriteString("    END AS swap_reason\n")
	b.WriteString("  FROM base\n")
	b.WriteString(")\n")
	b.WriteString("SELECT\n")
	b.WriteString("  device_id, start_time, end_time,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, dst_ip, src_ip) AS src_ip,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, src_ip, dst_ip) AS dst_ip,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, dst_port, src_port) AS src_port,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, src_port, dst_port) AS dst_port,\n")
	b.WriteString("  protocol_lc AS protocol,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, bytes_to_client, bytes_to_srv) AS bytes_to_srv,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, bytes_to_srv, bytes_to_client) AS bytes_to_client,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, pckt_to_client, pckt_to_srv) AS pckt_to_srv,\n")
	b.WriteString("  IF(swap_reason IS NOT NULL, pckt_to_srv, pckt_to_client) AS pckt_to_client\n")
	b.WriteString("FROM decide;\n")

	return b.String()
}

func privateServerSwapReason(tuple syntrail.ServerTuple) string {
	return fmt.Sprintf(
		"private_server_%s_%d_%s_seen_as_src_artifact",
		reasonPart(tuple.DstIP.String()),
		tuple.DstPort,
		reasonPart(string(tuple.Protocol)),
	)
}

func reasonPart(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_' || r == '.':
			return '_'
		default:
			return '_'
		}
	}, value)
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
