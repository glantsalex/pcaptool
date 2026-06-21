package syntrail

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

// TimestampLayout is the UTC timestamp format used in SYN trail CSV output.
const TimestampLayout = "2006-01-02 15:04:05.000"

// FormatTimestampUTC formats ts as UTC with fixed millisecond precision.
func FormatTimestampUTC(ts time.Time) string {
	return ts.UTC().Format(TimestampLayout)
}

// SortTrail sorts records in place by source IP, timestamp, destination IP, and destination port.
func SortTrail(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]

		if cmp := compareAddr(left.SrcIP, right.SrcIP); cmp != 0 {
			return cmp < 0
		}
		if !left.Timestamp.Equal(right.Timestamp) {
			return left.Timestamp.Before(right.Timestamp)
		}
		if cmp := compareAddr(left.DstIP, right.DstIP); cmp != 0 {
			return cmp < 0
		}
		return left.DstPort < right.DstPort
	})
}

// Unique returns one record per source IP, destination IP, and destination port tuple.
func Unique(records []Record) []Record {
	seen := make(map[recordKey]struct{}, len(records))
	unique := make([]Record, 0, len(records))
	for _, record := range records {
		key := recordKey{
			srcIP:   record.SrcIP,
			dstIP:   record.DstIP,
			dstPort: record.DstPort,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, record)
	}

	sort.Slice(unique, func(i, j int) bool {
		left := unique[i]
		right := unique[j]

		if cmp := compareAddr(left.SrcIP, right.SrcIP); cmp != 0 {
			return cmp < 0
		}
		if cmp := compareAddr(left.DstIP, right.DstIP); cmp != 0 {
			return cmp < 0
		}
		return left.DstPort < right.DstPort
	})

	return unique
}

// WriteTrailCSV writes all records as SYN trail CSV, including a header row.
func WriteTrailCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_ip", "dst_port", "syn_timestamp_utc"}); err != nil {
		return fmt.Errorf("write SYN trail CSV header: %w", err)
	}

	SortTrail(records)
	for _, record := range records {
		if err := cw.Write([]string{
			record.SrcIP.String(),
			record.DstIP.String(),
			strconv.FormatUint(uint64(record.DstPort), 10),
			FormatTimestampUTC(record.Timestamp),
		}); err != nil {
			return fmt.Errorf("write SYN trail CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush SYN trail CSV: %w", err)
	}
	return nil
}

// WriteProtocolTrailCSV writes all records as protocol trail CSV, including a
// header row. An empty protocol is normalized to TCP for compatibility.
func WriteProtocolTrailCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_ip", "dst_port", "protocol", "trail_timestamp_utc"}); err != nil {
		return fmt.Errorf("write protocol trail CSV header: %w", err)
	}

	rows := make([]protocolTrailRow, len(records))
	for i, record := range records {
		rows[i] = protocolTrailRow{
			record:   record,
			protocol: normalizedProtocol(record.Protocol),
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return protocolTrailRowLess(rows[i], rows[j])
	})

	for _, row := range rows {
		if err := cw.Write([]string{
			row.record.SrcIP.String(),
			row.record.DstIP.String(),
			strconv.FormatUint(uint64(row.record.DstPort), 10),
			string(row.protocol),
			FormatTimestampUTC(row.record.Timestamp),
		}); err != nil {
			return fmt.Errorf("write protocol trail CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush protocol trail CSV: %w", err)
	}
	return nil
}

// WriteTCPProtocolTrailCSV writes TCP records as protocol trail CSV, including
// a header row. Records with an empty protocol are treated as TCP.
func WriteTCPProtocolTrailCSV(w io.Writer, records []Record) error {
	return WriteProtocolTrailCSV(w, tcpRecords(records))
}

// WriteUniqueCSV writes deduplicated SYN trail tuples as CSV, including a header row.
func WriteUniqueCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_ip", "dst_port"}); err != nil {
		return fmt.Errorf("write unique SYN trail CSV header: %w", err)
	}

	for _, record := range Unique(records) {
		if err := cw.Write([]string{
			record.SrcIP.String(),
			record.DstIP.String(),
			strconv.FormatUint(uint64(record.DstPort), 10),
		}); err != nil {
			return fmt.Errorf("write unique SYN trail CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush unique SYN trail CSV: %w", err)
	}
	return nil
}

// WriteTCPUniqueCSV writes deduplicated TCP SYN trail tuples as CSV, including a header row.
func WriteTCPUniqueCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_ip", "dst_port", "protocol"}); err != nil {
		return fmt.Errorf("write unique TCP SYN trail CSV header: %w", err)
	}

	for _, record := range Unique(records) {
		if err := cw.Write([]string{
			record.SrcIP.String(),
			record.DstIP.String(),
			strconv.FormatUint(uint64(record.DstPort), 10),
			"tcp",
		}); err != nil {
			return fmt.Errorf("write unique TCP SYN trail CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush unique TCP SYN trail CSV: %w", err)
	}
	return nil
}

// WriteProtocolUniqueCSV writes deduplicated protocol trail tuples as CSV,
// including a header row. An empty protocol is normalized to TCP for compatibility.
func WriteProtocolUniqueCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_ip", "dst_port", "protocol"}); err != nil {
		return fmt.Errorf("write unique protocol trail CSV header: %w", err)
	}

	for _, row := range uniqueProtocolRows(records) {
		if err := cw.Write([]string{
			row.srcIP.String(),
			row.dstIP.String(),
			strconv.FormatUint(uint64(row.dstPort), 10),
			string(row.protocol),
		}); err != nil {
			return fmt.Errorf("write unique protocol trail CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush unique protocol trail CSV: %w", err)
	}
	return nil
}

// WritePrivateServersCSV writes deduplicated private server TCP SYN tuples as CSV, including a header row.
func WritePrivateServersCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"dst_ip", "dst_port", "protocol"}); err != nil {
		return fmt.Errorf("write private servers SYN CSV header: %w", err)
	}

	for _, row := range uniquePrivateServerRows(records) {
		if err := cw.Write([]string{
			row.dstIP.String(),
			strconv.FormatUint(uint64(row.dstPort), 10),
			row.protocol,
		}); err != nil {
			return fmt.Errorf("write private servers SYN CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush private servers SYN CSV: %w", err)
	}
	return nil
}

// WritePublicServersCSV writes deduplicated public server tuples as CSV,
// including a header row. An empty protocol is normalized to TCP for compatibility.
func WritePublicServersCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"dst_ip", "dst_port", "protocol"}); err != nil {
		return fmt.Errorf("write public servers CSV header: %w", err)
	}

	for _, row := range uniquePublicServerRows(records) {
		if err := cw.Write([]string{
			row.dstIP.String(),
			strconv.FormatUint(uint64(row.dstPort), 10),
			string(row.protocol),
		}); err != nil {
			return fmt.Errorf("write public servers CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush public servers CSV: %w", err)
	}
	return nil
}

// WritePrivateProbesCSV writes deduplicated private probe TCP SYN tuples as CSV, including a header row.
func WritePrivateProbesCSV(w io.Writer, records []Record) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"src_ip", "dst_port", "protocol"}); err != nil {
		return fmt.Errorf("write private probes SYN CSV header: %w", err)
	}

	for _, row := range uniquePrivateProbeRows(records) {
		if err := cw.Write([]string{
			row.srcIP.String(),
			strconv.FormatUint(uint64(row.dstPort), 10),
			row.protocol,
		}); err != nil {
			return fmt.Errorf("write private probes SYN CSV record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush private probes SYN CSV: %w", err)
	}
	return nil
}

type recordKey struct {
	srcIP   netip.Addr
	dstIP   netip.Addr
	dstPort uint16
}

type protocolTrailRow struct {
	record   Record
	protocol Protocol
}

type protocolUniqueRow struct {
	srcIP    netip.Addr
	dstIP    netip.Addr
	dstPort  uint16
	protocol Protocol
}

type privateServerRow struct {
	dstIP    netip.Addr
	dstPort  uint16
	protocol string
}

type publicServerRow struct {
	dstIP    netip.Addr
	dstPort  uint16
	protocol Protocol
}

type privateProbeRow struct {
	srcIP    netip.Addr
	dstPort  uint16
	protocol string
}

func protocolTrailRowLess(left, right protocolTrailRow) bool {
	leftRank := protocolRank(left.protocol)
	rightRank := protocolRank(right.protocol)
	if leftRank != rightRank {
		return leftRank < rightRank
	}
	if cmp := compareAddr(left.record.SrcIP, right.record.SrcIP); cmp != 0 {
		return cmp < 0
	}
	if !left.record.Timestamp.Equal(right.record.Timestamp) {
		return left.record.Timestamp.Before(right.record.Timestamp)
	}
	if cmp := compareAddr(left.record.DstIP, right.record.DstIP); cmp != 0 {
		return cmp < 0
	}
	return left.record.DstPort < right.record.DstPort
}

func protocolRank(protocol Protocol) int {
	switch protocol {
	case ProtocolTCP:
		return 0
	case ProtocolUDP:
		return 1
	default:
		return 2
	}
}

func normalizedProtocol(protocol Protocol) Protocol {
	if protocol == "" {
		return ProtocolTCP
	}
	return protocol
}

func tcpRecords(records []Record) []Record {
	filtered := make([]Record, 0, len(records))
	for _, record := range records {
		if normalizedProtocol(record.Protocol) != ProtocolTCP {
			continue
		}
		record.Protocol = ProtocolTCP
		filtered = append(filtered, record)
	}
	return filtered
}

func uniqueProtocolRows(records []Record) []protocolUniqueRow {
	seen := make(map[protocolUniqueRow]struct{}, len(records))
	rows := make([]protocolUniqueRow, 0, len(records))
	for _, record := range records {
		row := protocolUniqueRow{
			srcIP:    record.SrcIP,
			dstIP:    record.DstIP,
			dstPort:  record.DstPort,
			protocol: normalizedProtocol(record.Protocol),
		}
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		left := rows[i]
		right := rows[j]

		if leftRank, rightRank := protocolRank(left.protocol), protocolRank(right.protocol); leftRank != rightRank {
			return leftRank < rightRank
		}
		if cmp := compareAddr(left.srcIP, right.srcIP); cmp != 0 {
			return cmp < 0
		}
		if cmp := compareAddr(left.dstIP, right.dstIP); cmp != 0 {
			return cmp < 0
		}
		if left.dstPort != right.dstPort {
			return left.dstPort < right.dstPort
		}
		return left.protocol < right.protocol
	})

	return rows
}

func uniquePrivateServerRows(records []Record) []privateServerRow {
	seen := make(map[privateServerRow]struct{}, len(records))
	rows := make([]privateServerRow, 0, len(records))
	for _, record := range records {
		row := privateServerRow{
			dstIP:    record.DstIP,
			dstPort:  record.DstPort,
			protocol: "tcp",
		}
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		left := rows[i]
		right := rows[j]

		if cmp := compareAddr(left.dstIP, right.dstIP); cmp != 0 {
			return cmp < 0
		}
		if left.dstPort != right.dstPort {
			return left.dstPort < right.dstPort
		}
		return left.protocol < right.protocol
	})

	return rows
}

func uniquePublicServerRows(records []Record) []publicServerRow {
	seen := make(map[publicServerRow]struct{}, len(records))
	rows := make([]publicServerRow, 0, len(records))
	for _, record := range records {
		row := publicServerRow{
			dstIP:    record.DstIP,
			dstPort:  record.DstPort,
			protocol: normalizedProtocol(record.Protocol),
		}
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		left := rows[i]
		right := rows[j]

		if leftRank, rightRank := protocolRank(left.protocol), protocolRank(right.protocol); leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.dstPort != right.dstPort {
			return left.dstPort < right.dstPort
		}
		if cmp := compareAddr(left.dstIP, right.dstIP); cmp != 0 {
			return cmp < 0
		}
		return left.protocol < right.protocol
	})

	return rows
}

func uniquePrivateProbeRows(records []Record) []privateProbeRow {
	seen := make(map[privateProbeRow]struct{}, len(records))
	rows := make([]privateProbeRow, 0, len(records))
	for _, record := range records {
		row := privateProbeRow{
			srcIP:    record.SrcIP,
			dstPort:  record.DstPort,
			protocol: "tcp",
		}
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		left := rows[i]
		right := rows[j]

		if cmp := compareAddr(left.srcIP, right.srcIP); cmp != 0 {
			return cmp < 0
		}
		if left.dstPort != right.dstPort {
			return left.dstPort < right.dstPort
		}
		return left.protocol < right.protocol
	})

	return rows
}

func compareAddr(left, right netip.Addr) int {
	if left.Is4() && right.Is4() {
		leftOctets := left.As4()
		rightOctets := right.As4()
		for i := range leftOctets {
			switch {
			case leftOctets[i] < rightOctets[i]:
				return -1
			case leftOctets[i] > rightOctets[i]:
				return 1
			}
		}
		return 0
	}
	return left.Compare(right)
}
