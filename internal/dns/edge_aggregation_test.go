package dns

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	"github.com/google/gopacket"
)

func TestEdgeAccumulatorMatchesLegacyFileOrderMerge(t *testing.T) {
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	batches := make([][]connectivity.Edge, 300)
	for fileIdx := range batches {
		batches[fileIdx] = []connectivity.Edge{
			{
				IssuerIP:      "10.0.0.1",
				DstIP:         "198.51.100.1",
				Protocol:      connectivity.ProtoTCP,
				Port:          443,
				FirstSeen:     t0.Add(time.Duration(fileIdx) * time.Minute),
				ObservedTimes: []time.Time{t0.Add(time.Duration(fileIdx) * time.Minute)},
			},
			{
				IssuerIP:  "10.0.0.2",
				DstIP:     "203.0.113.2",
				Protocol:  connectivity.ProtoUDP,
				Port:      1234,
				FirstSeen: t0.Add(time.Duration(400-fileIdx) * time.Second),
			},
		}
	}
	// Exercise duplicate observations, out-of-order timestamps, and the bounded
	// earliest-plus-latest timestamp rule used by the production merger.
	batches[3][0].ObservedTimes = []time.Time{t0.Add(5 * time.Hour), t0.Add(-time.Hour), t0.Add(3 * time.Minute)}
	batches[7][0].ObservedTimes = append([]time.Time(nil), batches[3][0].ObservedTimes...)

	want := legacyFlattenEdgeBatches(batches)
	acc := newEdgeAccumulator()
	for _, batch := range batches {
		acc.merge(batch)
	}
	got := acc.edges()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("incremental merge differs from legacy file-order merge\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRunBoundedOrderedEdgeScansBoundsSlowFrontier(t *testing.T) {
	const (
		totalFiles = 24
		workers    = 4
	)

	releaseFirst := make(chan struct{})
	started := make(chan int, totalFiles)
	finishedBeforeFirst := make(chan struct{}, workers-1)

	scan := func(ctx context.Context, idx int) ([]connectivity.Edge, error) {
		started <- idx
		if idx == 0 {
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else if idx < workers {
			finishedBeforeFirst <- struct{}{}
		}
		return []connectivity.Edge{{IssuerIP: "10.0.0.1", DstIP: "198.51.100.1", Protocol: connectivity.ProtoTCP, Port: uint16(idx + 1)}}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	releasedFirst := false
	defer func() {
		if !releasedFirst {
			close(releaseFirst)
		}
	}()

	var committed []uint16
	done := make(chan struct{})
	var (
		stats orderedEdgeScanStats
		err   error
	)
	go func() {
		stats, err = runBoundedOrderedEdgeScans(ctx, totalFiles, workers, scan, func(edges []connectivity.Edge) {
			committed = append(committed, edges[0].Port)
		})
		close(done)
	}()

	for i := 0; i < workers-1; i++ {
		select {
		case <-finishedBeforeFirst:
		case <-ctx.Done():
			t.Fatal("timed out waiting for files behind the slow frontier")
		}
	}
	startedBeforeRelease := make(map[int]struct{}, workers)
	for len(startedBeforeRelease) < workers {
		select {
		case idx := <-started:
			startedBeforeRelease[idx] = struct{}{}
		case <-ctx.Done():
			t.Fatal("timed out waiting for initial dispatch window")
		}
	}
	for idx := range startedBeforeRelease {
		if idx >= workers {
			t.Fatalf("file %d dispatched while file 0 held the commit frontier", idx)
		}
	}
	close(releaseFirst)
	releasedFirst = true
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("ordered scan did not complete")
	}

	if err != nil {
		t.Fatalf("runBoundedOrderedEdgeScans: %v", err)
	}
	if stats.maxOutstanding > workers {
		t.Fatalf("max outstanding = %d, want <= %d", stats.maxOutstanding, workers)
	}
	if stats.maxPending > workers {
		t.Fatalf("max pending = %d, want <= %d", stats.maxPending, workers)
	}
	if len(committed) != totalFiles {
		t.Fatalf("committed %d batches, want %d", len(committed), totalFiles)
	}
	for idx, port := range committed {
		if want := uint16(idx + 1); port != want {
			t.Fatalf("committed[%d] port = %d, want %d", idx, port, want)
		}
	}
	close(started)
	for idx := range started {
		if idx < 0 || idx >= totalFiles {
			t.Fatalf("invalid dispatched file index %d", idx)
		}
	}
}

func TestRunBoundedOrderedEdgeScansEmptyAndNonPositiveWorkers(t *testing.T) {
	called := false
	stats, err := runBoundedOrderedEdgeScans(context.Background(), 0, 0, func(context.Context, int) ([]connectivity.Edge, error) {
		called = true
		return nil, nil
	}, func([]connectivity.Edge) {
		called = true
	})
	if err != nil || called || stats != (orderedEdgeScanStats{}) {
		t.Fatalf("empty scan = stats %+v err %v called %v, want zero/nil/false", stats, err, called)
	}

	var committed int
	stats, err = runBoundedOrderedEdgeScans(context.Background(), 3, -1, func(_ context.Context, idx int) ([]connectivity.Edge, error) {
		return []connectivity.Edge{{Port: uint16(idx + 1)}}, nil
	}, func([]connectivity.Edge) {
		committed++
	})
	if err != nil || committed != 3 || stats.maxOutstanding != 1 || stats.maxPending != 1 {
		t.Fatalf("single-worker scan = stats %+v err %v committed %d", stats, err, committed)
	}
}

func TestRunBoundedOrderedEdgeScansPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := runBoundedOrderedEdgeScans(ctx, 10, 3, func(context.Context, int) ([]connectivity.Edge, error) {
		called = true
		return nil, nil
	}, func([]connectivity.Edge) {
		called = true
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("pre-canceled scan dispatched work")
	}
}

func TestRunBoundedOrderedEdgeScansCancelsWorkersOnError(t *testing.T) {
	wantErr := errors.New("scan failed")
	workerCanceled := make(chan struct{})
	scan := func(ctx context.Context, idx int) ([]connectivity.Edge, error) {
		switch idx {
		case 0:
			<-ctx.Done()
			close(workerCanceled)
			return nil, ctx.Err()
		case 1:
			return nil, wantErr
		default:
			return nil, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := runBoundedOrderedEdgeScans(ctx, 20, 2, scan, func([]connectivity.Edge) {})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	select {
	case <-workerCanceled:
	case <-time.After(time.Second):
		t.Fatal("peer worker was not canceled after scan error")
	}
}

func TestAttachConnectionsCancellationAndOpenErrorReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(
		ctx, []string{"not-opened-after-cancellation.pcap"}, nil, false, false, nil, false, nil, nil, 0,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled connection scan error = %v, want context.Canceled", err)
	}

	missing := filepath.Join(t.TempDir(), "missing.pcap")
	_, _, err = AttachConnectionsAndCollectEdgesFromPCAPs(
		context.Background(), []string{missing}, nil, false, false, nil, false, nil, nil, 0,
	)
	if err == nil || !strings.Contains(err.Error(), "open pcap "+missing) {
		t.Fatalf("missing capture error = %v, want path-specific open error", err)
	}
}

func TestAttachConnectionsCancellationJoinsPacketReader(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	packet := buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "198.51.100.1", 41000, 443, true, false)
	packets := make([]dnsAdmissionPacket, 1100)
	for idx := range packets {
		packets[idx] = dnsAdmissionPacket{ts: base.Add(time.Duration(idx) * time.Millisecond), data: packet}
	}
	path := filepath.Join(t.TempDir(), "cancel-reader.pcap")
	writeConnectionAdmissionPCAP(t, path, packets)

	type scanResult struct {
		edges []connectivity.Edge
		first FirstPacketInfo
		err   error
		calls int
	}
	for run := 0; run < 3; run++ {
		ctx, cancel := context.WithCancel(context.Background())
		resultCh := make(chan scanResult, 1)
		go func() {
			admissionCalls := 0
			admit := func(gopacket.Packet) bool {
				admissionCalls++
				if admissionCalls == 10 {
					cancel()
				}
				return true
			}
			edges, first, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
				ctx, []string{path}, nil, false, false, nil, false, nil, nil, 0,
				PacketScanOptions{PacketAdmission: admit},
			)
			resultCh <- scanResult{edges: edges, first: first, err: err, calls: admissionCalls}
		}()

		select {
		case result := <-resultCh:
			cancel()
			if !errors.Is(result.err, context.Canceled) {
				t.Fatalf("run %d canceled connection scan error = %v, want context.Canceled", run, result.err)
			}
			if result.calls < 10 {
				t.Fatalf("run %d admission calls = %d, want at least 10", run, result.calls)
			}
			if result.edges != nil || !result.first.Timestamp.IsZero() || result.first.PCAPFile != "" {
				t.Fatalf("run %d returned partial result on cancellation: edges=%#v first=%+v", run, result.edges, result.first)
			}
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("run %d did not join the asynchronous packet reader", run)
		}
	}
}

func TestAttachConnectionsPreservesFirstEightCandidateCap(t *testing.T) {
	const (
		issuer = "10.0.0.1"
		dst    = "198.51.100.1"
	)
	requestTime := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tx := &DNSTransaction{
		RequestTime:  requestTime,
		IssuerIP:     net.ParseIP(issuer),
		DNSName:      "candidate-cap.example",
		NameEvidence: EvDNSAnswer,
	}
	tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer)

	packets := make([]dnsAdmissionPacket, 0, maxCandidatesPerTX+1)
	for idx := 0; idx < maxCandidatesPerTX; idx++ {
		packets = append(packets, dnsAdmissionPacket{
			ts: requestTime.Add(time.Duration(idx+1) * 100 * time.Millisecond),
			data: buildConnectionInferenceTestTCPPacket(
				t, issuer, dst, uint16(50000+idx), uint16(4100+idx), true, false,
			),
		})
	}
	// This ninth observation is closer to the DNS request than every retained
	// candidate, but the legacy first-eight arrival cap intentionally excludes it.
	packets = append(packets, dnsAdmissionPacket{
		ts:   requestTime.Add(10 * time.Millisecond),
		data: buildConnectionInferenceTestTCPPacket(t, issuer, dst, 50009, 4999, true, false),
	})
	path := filepath.Join(t.TempDir(), "candidate-cap.pcap")
	writeConnectionAdmissionPCAP(t, path, packets)

	_, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(
		context.Background(), []string{path}, []*DNSTransaction{tx}, false, false, nil, false, nil, nil, 0,
	)
	if err != nil {
		t.Fatalf("connection scan: %v", err)
	}
	if tx.DestinationPort == nil || *tx.DestinationPort != 4100 {
		t.Fatalf("selected destination port = %v, want first-eight minimum 4100", tx.DestinationPort)
	}
	if len(tx.ObservedEndpointBindings) != maxCandidatesPerTX+1 {
		t.Fatalf("observed bindings = %d, want all %d observations", len(tx.ObservedEndpointBindings), maxCandidatesPerTX+1)
	}
	if !tx.HasObservedEndpointBinding(dst, L4ProtoTCP, 4999, requestTime.Add(10*time.Millisecond)) {
		t.Fatal("ninth observation was omitted from endpoint bindings")
	}
}

func legacyFlattenEdgeBatches(batches [][]connectivity.Edge) []connectivity.Edge {
	type edgeKey struct {
		issuer string
		dst    string
		proto  connectivity.L4Proto
		port   uint16
	}

	seenEdges := make(map[edgeKey]int, 65536)
	var out []connectivity.Edge
	for _, batch := range batches {
		for _, e := range batch {
			k := edgeKey{issuer: e.IssuerIP, dst: e.DstIP, proto: e.Protocol, port: e.Port}
			if idx, ok := seenEdges[k]; ok {
				times := e.ObservedTimes
				if len(times) == 0 && !e.FirstSeen.IsZero() {
					times = []time.Time{e.FirstSeen}
				}
				out[idx].ObservedTimes = connectivity.MergeEdgeObservedTimes(out[idx].ObservedTimes, times...)
				if len(out[idx].ObservedTimes) > 0 {
					out[idx].FirstSeen = out[idx].ObservedTimes[0]
				}
				continue
			}
			if len(e.ObservedTimes) == 0 && !e.FirstSeen.IsZero() {
				e.ObservedTimes = []time.Time{e.FirstSeen.UTC()}
			}
			seenEdges[k] = len(out)
			out = append(out, e)
		}
	}
	return out
}
