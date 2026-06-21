package syntrail

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestFormatTimestampUTCUsesUTC(t *testing.T) {
	loc := time.FixedZone("test", 2*60*60)
	ts := time.Date(2024, 3, 5, 12, 30, 15, 987_000_000, loc)

	got := FormatTimestampUTC(ts)
	want := "2024-03-05 10:30:15.987"

	if got != want {
		t.Fatalf("FormatTimestampUTC() = %q, want %q", got, want)
	}
}

func TestFormatTimestampUTCUsesExactMillisecondPrecision(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 30, 15, 987_654_321, time.UTC)

	got := FormatTimestampUTC(ts)
	want := "2024-03-05 12:30:15.987"

	if got != want {
		t.Fatalf("FormatTimestampUTC() = %q, want %q", got, want)
	}
}

func TestSortTrail(t *testing.T) {
	base := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	a := testCSVRecord("10.0.0.2", "10.0.0.1", 443, base.Add(time.Second))
	b := testCSVRecord("10.0.0.1", "10.0.0.9", 443, base.Add(2*time.Second))
	c := testCSVRecord("10.0.0.1", "10.0.0.2", 8080, base)
	d := testCSVRecord("10.0.0.1", "10.0.0.2", 80, base)
	e := testCSVRecord("10.0.0.1", "10.0.0.1", 443, base)

	records := []Record{a, b, c, d, e}
	SortTrail(records)

	want := []Record{e, d, c, b, a}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("SortTrail() = %+v, want %+v", records, want)
	}
}

func TestUniqueSortsByTuple(t *testing.T) {
	base := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	a := testCSVRecord("10.0.0.2", "10.0.0.1", 443, base)
	b := testCSVRecord("10.0.0.1", "10.0.0.9", 443, base)
	c := testCSVRecord("10.0.0.1", "10.0.0.2", 8080, base)
	d := testCSVRecord("10.0.0.1", "10.0.0.2", 80, base)
	e := testCSVRecord("10.0.0.1", "10.0.0.1", 443, base)

	got := Unique([]Record{a, b, c, d, e})
	want := []Record{e, d, c, b, a}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unique() = %+v, want %+v", got, want)
	}
}

func TestUniqueDedupesByTupleAndIgnoresTimestamp(t *testing.T) {
	older := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	duplicateOlder := testCSVRecord("10.0.0.1", "10.0.0.2", 443, older)
	duplicateNewer := testCSVRecord("10.0.0.1", "10.0.0.2", 443, newer)
	distinctPort := testCSVRecord("10.0.0.1", "10.0.0.2", 8443, newer)

	got := Unique([]Record{duplicateOlder, duplicateNewer, distinctPort})
	want := []Record{duplicateOlder, distinctPort}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unique() = %+v, want %+v", got, want)
	}
}

func TestWriteTrailCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTrailCSV(&buf, nil); err != nil {
		t.Fatalf("WriteTrailCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port,syn_timestamp_utc\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTrailCSV() = %q, want %q", got, want)
	}
}

func TestWriteTCPProtocolTrailCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPProtocolTrailCSV(&buf, nil); err != nil {
		t.Fatalf("WriteTCPProtocolTrailCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTCPProtocolTrailCSV() = %q, want %q", got, want)
	}
}

func TestWriteProtocolTrailCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteProtocolTrailCSV(&buf, nil); err != nil {
		t.Fatalf("WriteProtocolTrailCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteProtocolTrailCSV() = %q, want %q", got, want)
	}
}

func TestWriteTCPProtocolTrailCSVReturnsWriterError(t *testing.T) {
	writeErr := errors.New("write failed")

	err := WriteTCPProtocolTrailCSV(testCSVErrorWriter{err: writeErr}, nil)
	if !errors.Is(err, writeErr) {
		t.Fatalf("WriteTCPProtocolTrailCSV() error = %v, want wrapped %v", err, writeErr)
	}
}

func TestWriteProtocolTrailCSVReturnsWriterError(t *testing.T) {
	writeErr := errors.New("write failed")

	err := WriteProtocolTrailCSV(testCSVErrorWriter{err: writeErr}, nil)
	if !errors.Is(err, writeErr) {
		t.Fatalf("WriteProtocolTrailCSV() error = %v, want wrapped %v", err, writeErr)
	}
}

func TestProtocolTrailRowLessRanksTCPBeforeUDP(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	tcp := protocolTrailRow{
		record:   testCSVRecord("10.0.0.10", "10.0.0.10", 8443, ts),
		protocol: "tcp",
	}
	udp := protocolTrailRow{
		record:   testCSVRecord("10.0.0.1", "10.0.0.1", 53, ts.Add(-time.Hour)),
		protocol: "udp",
	}

	if !protocolTrailRowLess(tcp, udp) {
		t.Fatal("protocolTrailRowLess(tcp, udp) = false, want true")
	}
	if protocolTrailRowLess(udp, tcp) {
		t.Fatal("protocolTrailRowLess(udp, tcp) = true, want false")
	}
}

func TestWriteUniqueCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteUniqueCSV(&buf, nil); err != nil {
		t.Fatalf("WriteUniqueCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteUniqueCSV() = %q, want %q", got, want)
	}
}

func TestWriteTCPUniqueCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPUniqueCSV(&buf, nil); err != nil {
		t.Fatalf("WriteTCPUniqueCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port,protocol\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTCPUniqueCSV() = %q, want %q", got, want)
	}
}

func TestWriteProtocolUniqueCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteProtocolUniqueCSV(&buf, nil); err != nil {
		t.Fatalf("WriteProtocolUniqueCSV() error = %v", err)
	}

	want := "src_ip,dst_ip,dst_port,protocol\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteProtocolUniqueCSV() = %q, want %q", got, want)
	}
}

func TestWriteProtocolUniqueCSVReturnsWriterError(t *testing.T) {
	writeErr := errors.New("write failed")

	err := WriteProtocolUniqueCSV(testCSVErrorWriter{err: writeErr}, nil)
	if !errors.Is(err, writeErr) {
		t.Fatalf("WriteProtocolUniqueCSV() error = %v, want wrapped %v", err, writeErr)
	}
}

func TestWritePrivateServersCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePrivateServersCSV(&buf, nil); err != nil {
		t.Fatalf("WritePrivateServersCSV() error = %v", err)
	}

	want := "dst_ip,dst_port,protocol\n"
	if got := buf.String(); got != want {
		t.Fatalf("WritePrivateServersCSV() = %q, want %q", got, want)
	}
}

func TestWritePrivateProbesCSVEmptyWritesHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePrivateProbesCSV(&buf, nil); err != nil {
		t.Fatalf("WritePrivateProbesCSV() error = %v", err)
	}

	want := "src_ip,dst_port,protocol\n"
	if got := buf.String(); got != want {
		t.Fatalf("WritePrivateProbesCSV() = %q, want %q", got, want)
	}
}

func TestWriteTrailCSVIncludesAllRecords(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 123_000_000, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.2", "10.0.0.9", 443, late),
		testCSVRecord("10.0.0.1", "10.0.0.2", 443, late),
		testCSVRecord("10.0.0.1", "10.0.0.2", 443, early),
	}

	var buf bytes.Buffer
	if err := WriteTrailCSV(&buf, records); err != nil {
		t.Fatalf("WriteTrailCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,syn_timestamp_utc\n" +
		"10.0.0.1,10.0.0.2,443,2024-03-05 12:00:00.123\n" +
		"10.0.0.1,10.0.0.2,443,2024-03-05 12:00:01.123\n" +
		"10.0.0.2,10.0.0.9,443,2024-03-05 12:00:01.123\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTrailCSV() = %q, want %q", got, want)
	}
}

func TestWriteTCPProtocolTrailCSVIncludesProtocolSortsDeterministicallyAndPreservesInput(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 123_000_000, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.10", "10.0.0.1", 443, early),
		testCSVRecord("10.0.0.2", "10.0.0.10", 443, late),
		testCSVRecord("10.0.0.2", "10.0.0.2", 8443, late),
		testCSVRecord("10.0.0.2", "10.0.0.2", 443, late),
		testCSVRecord("10.0.0.2", "10.0.0.9", 443, early),
	}
	original := append([]Record(nil), records...)

	var buf bytes.Buffer
	if err := WriteTCPProtocolTrailCSV(&buf, records); err != nil {
		t.Fatalf("WriteTCPProtocolTrailCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n" +
		"10.0.0.2,10.0.0.9,443,tcp,2024-03-05 12:00:00.123\n" +
		"10.0.0.2,10.0.0.2,443,tcp,2024-03-05 12:00:01.123\n" +
		"10.0.0.2,10.0.0.2,8443,tcp,2024-03-05 12:00:01.123\n" +
		"10.0.0.2,10.0.0.10,443,tcp,2024-03-05 12:00:01.123\n" +
		"10.0.0.10,10.0.0.1,443,tcp,2024-03-05 12:00:00.123\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTCPProtocolTrailCSV() = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatalf("WriteTCPProtocolTrailCSV() mutated records: got %+v, want %+v", records, original)
	}
}

func TestWriteProtocolTrailCSVWritesActualProtocolSortsTCPBeforeUDPAndPreservesInput(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 123_000_000, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecordWithProtocol("10.0.0.1", "10.0.0.3", 123, late, Protocol("sctp")),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.2", 53, early, ProtocolUDP),
		testCSVRecordWithProtocol("10.0.0.10", "10.0.0.1", 443, early, ProtocolTCP),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.9", 8443, late, ""),
	}
	original := append([]Record(nil), records...)

	var buf bytes.Buffer
	if err := WriteProtocolTrailCSV(&buf, records); err != nil {
		t.Fatalf("WriteProtocolTrailCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n" +
		"10.0.0.2,10.0.0.9,8443,tcp,2024-03-05 12:00:01.123\n" +
		"10.0.0.10,10.0.0.1,443,tcp,2024-03-05 12:00:00.123\n" +
		"10.0.0.2,10.0.0.2,53,udp,2024-03-05 12:00:00.123\n" +
		"10.0.0.1,10.0.0.3,123,sctp,2024-03-05 12:00:01.123\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteProtocolTrailCSV() = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatalf("WriteProtocolTrailCSV() mutated records: got %+v, want %+v", records, original)
	}
}

func TestWriteTCPProtocolTrailCSVExcludesUDPAndTreatsEmptyProtocolAsTCP(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	records := []Record{
		testCSVRecordWithProtocol("10.0.0.1", "10.0.0.2", 443, ts, ""),
		testCSVRecordWithProtocol("10.0.0.1", "10.0.0.3", 53, ts, ProtocolUDP),
	}

	var buf bytes.Buffer
	if err := WriteTCPProtocolTrailCSV(&buf, records); err != nil {
		t.Fatalf("WriteTCPProtocolTrailCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,protocol,trail_timestamp_utc\n" +
		"10.0.0.1,10.0.0.2,443,tcp,2024-03-05 12:00:00.000\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTCPProtocolTrailCSV() = %q, want %q", got, want)
	}
}

func TestWriteUniqueCSVIncludesDedupedRecordsOnly(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.2", "10.0.0.9", 443, late),
		testCSVRecord("10.0.0.1", "10.0.0.2", 443, early),
		testCSVRecord("10.0.0.1", "10.0.0.2", 443, late),
		testCSVRecord("10.0.0.1", "10.0.0.2", 8443, late),
	}

	var buf bytes.Buffer
	if err := WriteUniqueCSV(&buf, records); err != nil {
		t.Fatalf("WriteUniqueCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port\n" +
		"10.0.0.1,10.0.0.2,443\n" +
		"10.0.0.1,10.0.0.2,8443\n" +
		"10.0.0.2,10.0.0.9,443\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteUniqueCSV() = %q, want %q", got, want)
	}
}

func TestWritePrivateServersCSVIncludesProtocolDedupesAndSortsByTuple(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.1", "10.0.0.10", 443, late),
		testCSVRecord("10.0.0.2", "10.0.0.2", 8443, late),
		testCSVRecord("10.0.0.3", "10.0.0.2", 443, early),
		testCSVRecord("10.0.0.4", "10.0.0.2", 443, late),
	}

	var buf bytes.Buffer
	if err := WritePrivateServersCSV(&buf, records); err != nil {
		t.Fatalf("WritePrivateServersCSV() error = %v", err)
	}

	want := "" +
		"dst_ip,dst_port,protocol\n" +
		"10.0.0.2,443,tcp\n" +
		"10.0.0.2,8443,tcp\n" +
		"10.0.0.10,443,tcp\n"
	if got := buf.String(); got != want {
		t.Fatalf("WritePrivateServersCSV() = %q, want %q", got, want)
	}
}

func TestWritePrivateProbesCSVIncludesProtocolDedupesAndSortsByTuple(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.10", "10.0.0.1", 443, late),
		testCSVRecord("10.0.0.2", "10.0.0.10", 443, early),
		testCSVRecord("10.0.0.2", "10.0.0.2", 8443, late),
		testCSVRecord("10.0.0.2", "10.0.0.3", 443, late),
	}

	var buf bytes.Buffer
	if err := WritePrivateProbesCSV(&buf, records); err != nil {
		t.Fatalf("WritePrivateProbesCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_port,protocol\n" +
		"10.0.0.2,443,tcp\n" +
		"10.0.0.2,8443,tcp\n" +
		"10.0.0.10,443,tcp\n"
	if got := buf.String(); got != want {
		t.Fatalf("WritePrivateProbesCSV() = %q, want %q", got, want)
	}
}

func TestWriteTCPUniqueCSVIncludesProtocolDedupesAndSortsByTuple(t *testing.T) {
	early := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Second)
	records := []Record{
		testCSVRecord("10.0.0.10", "10.0.0.1", 443, late),
		testCSVRecord("10.0.0.2", "10.0.0.10", 443, early),
		testCSVRecord("10.0.0.2", "10.0.0.2", 8443, late),
		testCSVRecord("10.0.0.2", "10.0.0.2", 443, early),
		testCSVRecord("10.0.0.2", "10.0.0.2", 443, late),
	}

	var buf bytes.Buffer
	if err := WriteTCPUniqueCSV(&buf, records); err != nil {
		t.Fatalf("WriteTCPUniqueCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,protocol\n" +
		"10.0.0.2,10.0.0.2,443,tcp\n" +
		"10.0.0.2,10.0.0.2,8443,tcp\n" +
		"10.0.0.2,10.0.0.10,443,tcp\n" +
		"10.0.0.10,10.0.0.1,443,tcp\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteTCPUniqueCSV() = %q, want %q", got, want)
	}
}

func TestWriteProtocolUniqueCSVNormalizesDedupesSortsAndPreservesInput(t *testing.T) {
	ts := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	records := []Record{
		testCSVRecordWithProtocol("10.0.0.10", "10.0.0.2", 443, ts, ProtocolTCP),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.10", 443, ts, ProtocolUDP),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.2", 8443, ts, ProtocolTCP),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.2", 443, ts, ""),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.2", 443, ts.Add(time.Second), ProtocolTCP),
		testCSVRecordWithProtocol("10.0.0.2", "10.0.0.2", 443, ts, ProtocolUDP),
		testCSVRecordWithProtocol("10.0.0.1", "10.0.0.3", 123, ts, Protocol("sctp")),
		testCSVRecordWithProtocol("10.0.0.1", "10.0.0.3", 123, ts, Protocol("icmp")),
	}
	original := append([]Record(nil), records...)

	var buf bytes.Buffer
	if err := WriteProtocolUniqueCSV(&buf, records); err != nil {
		t.Fatalf("WriteProtocolUniqueCSV() error = %v", err)
	}

	want := "" +
		"src_ip,dst_ip,dst_port,protocol\n" +
		"10.0.0.2,10.0.0.2,443,tcp\n" +
		"10.0.0.2,10.0.0.2,8443,tcp\n" +
		"10.0.0.10,10.0.0.2,443,tcp\n" +
		"10.0.0.2,10.0.0.2,443,udp\n" +
		"10.0.0.2,10.0.0.10,443,udp\n" +
		"10.0.0.1,10.0.0.3,123,icmp\n" +
		"10.0.0.1,10.0.0.3,123,sctp\n"
	if got := buf.String(); got != want {
		t.Fatalf("WriteProtocolUniqueCSV() = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(records, original) {
		t.Fatalf("WriteProtocolUniqueCSV() mutated records: got %+v, want %+v", records, original)
	}
}

func testCSVRecord(src, dst string, dstPort uint16, timestamp time.Time) Record {
	return testCSVRecordWithProtocol(src, dst, dstPort, timestamp, ProtocolTCP)
}

func testCSVRecordWithProtocol(src, dst string, dstPort uint16, timestamp time.Time, protocol Protocol) Record {
	return Record{
		SrcIP:     netip.MustParseAddr(src),
		DstIP:     netip.MustParseAddr(dst),
		DstPort:   dstPort,
		Protocol:  protocol,
		Timestamp: timestamp,
	}
}

type testCSVErrorWriter struct {
	err error
}

func (w testCSVErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
