package syntrail

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pcaputil "github.com/aglants/pcaptool/internal/pcap"
)

// legacyMergeScanFileResults freezes the pre-optimization merge contract:
// every TCP observation remains in file/packet order, followed by UDP tuples
// in first-appearance order with the earliest observed timestamp retained.
func legacyMergeScanFileResults(results []scanFileResult) []Record {
	var tcpRecords []Record
	udpRecords := make(map[observedRecordKey]Record)
	var udpOrder []observedRecordKey

	for _, result := range results {
		for _, record := range result.records {
			if record.Protocol != ProtocolUDP {
				tcpRecords = append(tcpRecords, record)
				continue
			}
			legacyAddEarliestRecord(udpRecords, &udpOrder, record)
		}
	}

	return legacyAppendOrderedRecords(tcpRecords, udpRecords, udpOrder)
}

func legacyAddEarliestRecord(records map[observedRecordKey]Record, order *[]observedRecordKey, record Record) {
	key := observedRecordKey{
		srcIP:    record.SrcIP,
		dstIP:    record.DstIP,
		dstPort:  record.DstPort,
		protocol: record.Protocol,
	}
	current, ok := records[key]
	if !ok {
		records[key] = record
		*order = append(*order, key)
		return
	}
	if record.Timestamp.Before(current.Timestamp) {
		records[key] = record
	}
}

func legacyAppendOrderedRecords(prefix []Record, records map[observedRecordKey]Record, order []observedRecordKey) []Record {
	if len(order) == 0 {
		return prefix
	}
	combined := make([]Record, 0, len(prefix)+len(order))
	combined = append(combined, prefix...)
	for _, key := range order {
		combined = append(combined, records[key])
	}
	return combined
}

func TestScanRecordAccumulatorMatchesFrozenLegacyContract(t *testing.T) {
	t.Parallel()

	for _, seed := range []int64{1, 7, 41, 301686} {
		seed := seed
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			t.Parallel()

			results := generatedScanFileResults(seed, 240, 48)
			want := legacyMergeScanFileResults(results)
			got := accumulatedScanFileResults(results)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("incremental accumulator differs from frozen legacy contract\ngot:  %+v\nwant: %+v", got, want)
			}
		})
	}
}

func TestScanRecordAccumulatorPreservesLateEarliestUDPAndTCPDuplicates(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tcp := Record{
		SrcIP:     netip.MustParseAddr("10.0.0.1"),
		DstIP:     netip.MustParseAddr("203.0.113.1"),
		DstPort:   443,
		Protocol:  ProtocolTCP,
		Timestamp: base,
	}
	udpFirst := Record{
		SrcIP:     netip.MustParseAddr("10.0.0.2"),
		DstIP:     netip.MustParseAddr("203.0.113.2"),
		DstPort:   53,
		Protocol:  ProtocolUDP,
		Timestamp: base.Add(10 * time.Second),
	}
	udpSecond := Record{
		SrcIP:     netip.MustParseAddr("10.0.0.3"),
		DstIP:     netip.MustParseAddr("203.0.113.3"),
		DstPort:   123,
		Protocol:  ProtocolUDP,
		Timestamp: base.Add(2 * time.Second),
	}
	udpEarlier := udpFirst
	udpEarlier.Timestamp = base.Add(-time.Second)

	accumulator := newScanRecordAccumulator()
	accumulator.add([]Record{tcp, tcp, udpFirst, udpSecond})
	accumulator.add([]Record{udpEarlier})

	want := []Record{tcp, tcp, udpEarlier, udpSecond}
	if got := accumulator.records(); !reflect.DeepEqual(got, want) {
		t.Fatalf("scanRecordAccumulator.records() = %+v, want %+v", got, want)
	}
}

func TestScanFilesConcurrentBoundsOutstandingFileBatches(t *testing.T) {
	t.Parallel()

	const (
		fileCount = 12
		workers   = 3
	)
	files := make([]string, fileCount)
	for i := range files {
		files[i] = strconv.Itoa(i)
	}

	started := make(chan int, fileCount)
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(release)

	scanner := func(ctx context.Context, path string, _ pcaputil.PacketAdmission) ([]Record, error) {
		index, err := strconv.Atoi(path)
		if err != nil {
			return nil, err
		}
		started <- index
		if index == 0 {
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []Record{{
			SrcIP:     netip.AddrFrom4([4]byte{10, 0, 0, byte(index + 1)}),
			DstIP:     netip.MustParseAddr("203.0.113.1"),
			DstPort:   443,
			Protocol:  ProtocolTCP,
			Timestamp: time.Unix(int64(index), 0).UTC(),
		}}, nil
	}

	type scanOutcome struct {
		records []Record
		err     error
	}
	outcomeCh := make(chan scanOutcome, 1)
	go func() {
		records, err := scanFilesConcurrentWithScanner(
			context.Background(), files, workers, nil, nil, scanner,
		)
		outcomeCh <- scanOutcome{records: records, err: err}
	}()

	seen := make(map[int]struct{}, workers)
	for len(seen) < workers {
		select {
		case index := <-started:
			seen[index] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the initial bounded scan frontier")
		}
	}
	for i := 0; i < workers; i++ {
		if _, ok := seen[i]; !ok {
			t.Fatalf("initial scan frontier = %v, want file indexes [0,%d)", seen, workers)
		}
	}

	select {
	case index := <-started:
		t.Fatalf("file index %d started while file 0 blocked; outstanding frontier exceeds %d", index, workers)
	case <-time.After(50 * time.Millisecond):
	}

	release()
	select {
	case outcome := <-outcomeCh:
		if outcome.err != nil {
			t.Fatalf("scanFilesConcurrentWithScanner() error = %v", outcome.err)
		}
		if len(outcome.records) != fileCount {
			t.Fatalf("record count = %d, want %d", len(outcome.records), fileCount)
		}
		for i, record := range outcome.records {
			want := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
			if record.SrcIP != want {
				t.Fatalf("record %d source = %v, want %v; file order was not preserved", i, record.SrcIP, want)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bounded concurrent scan to finish")
	}
}

func TestScanFilesConcurrentCancelsPeersAndReturnsNoPartialRecordsOnError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("synthetic scan failure")
	firstStarted := make(chan struct{})
	scanner := func(ctx context.Context, path string, _ pcaputil.PacketAdmission) ([]Record, error) {
		switch path {
		case "first":
			close(firstStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		case "error":
			<-firstStarted
			return nil, wantErr
		default:
			return []Record{{Protocol: ProtocolTCP}}, nil
		}
	}

	records, err := scanFilesConcurrentWithScanner(
		context.Background(), []string{"first", "error", "must-not-start"}, 2, nil, nil, scanner,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("scanFilesConcurrentWithScanner() error = %v, want %v", err, wantErr)
	}
	if records != nil {
		t.Fatalf("scanFilesConcurrentWithScanner() records = %+v, want nil", records)
	}
}

func TestScanFilesConcurrentParentCancellationReturnsNoPartialRecords(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var startOnce sync.Once
	scanner := func(ctx context.Context, _ string, _ pcaputil.PacketAdmission) ([]Record, error) {
		startOnce.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}

	type scanOutcome struct {
		records []Record
		err     error
	}
	outcomeCh := make(chan scanOutcome, 1)
	go func() {
		records, err := scanFilesConcurrentWithScanner(
			ctx, []string{"first", "second"}, 2, nil, nil, scanner,
		)
		outcomeCh <- scanOutcome{records: records, err: err}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for concurrent scan to start")
	}
	cancel()
	select {
	case outcome := <-outcomeCh:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("scanFilesConcurrentWithScanner() error = %v, want context.Canceled", outcome.err)
		}
		if outcome.records != nil {
			t.Fatalf("scanFilesConcurrentWithScanner() records = %+v, want nil", outcome.records)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canceled concurrent scan to finish")
	}
}

func TestScanFilesConcurrentPreCanceledContextDoesNotDeadlockOrStartScan(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	scanner := func(context.Context, string, pcaputil.PacketAdmission) ([]Record, error) {
		calls.Add(1)
		return []Record{{Protocol: ProtocolTCP}}, nil
	}

	type scanOutcome struct {
		records []Record
		err     error
	}
	outcomeCh := make(chan scanOutcome, 1)
	go func() {
		records, err := scanFilesConcurrentWithScanner(
			ctx, []string{"first", "second"}, 2, nil, nil, scanner,
		)
		outcomeCh <- scanOutcome{records: records, err: err}
	}()

	select {
	case outcome := <-outcomeCh:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("scanFilesConcurrentWithScanner() error = %v, want context.Canceled", outcome.err)
		}
		if outcome.records != nil {
			t.Fatalf("scanFilesConcurrentWithScanner() records = %+v, want nil", outcome.records)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("scanner calls = %d, want 0", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pre-canceled concurrent scan deadlocked")
	}
}

func TestScanFilesConcurrentCancellationBetweenCommitAndDispatchDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	scanner := func(context.Context, string, pcaputil.PacketAdmission) ([]Record, error) {
		calls.Add(1)
		return []Record{{Protocol: ProtocolTCP}}, nil
	}
	progress := func(done, _ int, _ string) {
		if done == 1 {
			cancel()
		}
	}

	type scanOutcome struct {
		records []Record
		err     error
	}
	outcomeCh := make(chan scanOutcome, 1)
	go func() {
		records, err := scanFilesConcurrentWithScanner(
			ctx, []string{"first", "must-not-start"}, 1, progress, nil, scanner,
		)
		outcomeCh <- scanOutcome{records: records, err: err}
	}()

	select {
	case outcome := <-outcomeCh:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("scanFilesConcurrentWithScanner() error = %v, want context.Canceled", outcome.err)
		}
		if outcome.records != nil {
			t.Fatalf("scanFilesConcurrentWithScanner() records = %+v, want nil", outcome.records)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("scanner calls = %d, want 1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent scan deadlocked after cancellation in the dispatch gap")
	}
}

func BenchmarkScanRecordAccumulatorLegacyShape(b *testing.B) {
	results := generatedScanFileResults(301686, 1_000, 256)
	b.Run("frozen_legacy", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if got := legacyMergeScanFileResults(results); len(got) == 0 {
				b.Fatal("legacyMergeScanFileResults() returned no records")
			}
		}
	})
	b.Run("incremental_accumulator", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if got := accumulatedScanFileResults(results); len(got) == 0 {
				b.Fatal("incremental accumulator returned no records")
			}
		}
	})
}

func accumulatedScanFileResults(results []scanFileResult) []Record {
	accumulator := newScanRecordAccumulator()
	for _, result := range results {
		accumulator.add(result.records)
	}
	return accumulator.records()
}

func generatedScanFileResults(seed int64, fileCount, recordsPerFile int) []scanFileResult {
	rng := rand.New(rand.NewSource(seed))
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	results := make([]scanFileResult, fileCount)
	for fileIndex := range results {
		records := make([]Record, 0, recordsPerFile)
		for recordIndex := 0; recordIndex < recordsPerFile; recordIndex++ {
			protocol := ProtocolTCP
			if recordIndex%3 == 0 {
				protocol = ProtocolUDP
			}
			srcOctet := byte(1 + rng.Intn(12))
			dstOctet := byte(1 + rng.Intn(20))
			records = append(records, Record{
				SrcIP:     netip.AddrFrom4([4]byte{10, 0, 0, srcOctet}),
				DstIP:     netip.AddrFrom4([4]byte{203, 0, 113, dstOctet}),
				DstPort:   uint16(1 + rng.Intn(8)),
				Protocol:  protocol,
				Timestamp: base.Add(time.Duration(rng.Int63n(int64(24 * time.Hour)))),
			})
		}
		results[fileIndex] = scanFileResult{
			index:   fileIndex,
			path:    fmt.Sprintf("capture-%06d.pcap", fileIndex),
			records: records,
		}
	}
	return results
}
