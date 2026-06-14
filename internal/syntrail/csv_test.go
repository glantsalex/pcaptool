package syntrail

import (
	"bytes"
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

func testCSVRecord(src, dst string, dstPort uint16, timestamp time.Time) Record {
	return Record{
		SrcIP:     netip.MustParseAddr(src),
		DstIP:     netip.MustParseAddr(dst),
		DstPort:   dstPort,
		Timestamp: timestamp,
	}
}
