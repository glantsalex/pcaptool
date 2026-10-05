package dns

import (
	"context"
	"sync"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
)

type edgeAggregationKey struct {
	issuer string
	dst    string
	proto  connectivity.L4Proto
	port   uint16
}

// edgeAccumulator incrementally applies the legacy file-order edge merge. It
// retains only the globally merged edges instead of every completed file's
// intermediate edge slice.
type edgeAccumulator struct {
	seen map[edgeAggregationKey]int
	out  []connectivity.Edge
}

func newEdgeAccumulator() *edgeAccumulator {
	return &edgeAccumulator{seen: make(map[edgeAggregationKey]int, 65536)}
}

func (a *edgeAccumulator) merge(batch []connectivity.Edge) {
	for _, e := range batch {
		key := edgeAggregationKey{
			issuer: e.IssuerIP,
			dst:    e.DstIP,
			proto:  e.Protocol,
			port:   e.Port,
		}
		if idx, ok := a.seen[key]; ok {
			times := e.ObservedTimes
			if len(times) == 0 && !e.FirstSeen.IsZero() {
				times = []time.Time{e.FirstSeen}
			}
			a.out[idx].ObservedTimes = connectivity.MergeEdgeObservedTimes(a.out[idx].ObservedTimes, times...)
			if len(a.out[idx].ObservedTimes) > 0 {
				a.out[idx].FirstSeen = a.out[idx].ObservedTimes[0]
			}
			continue
		}
		if len(e.ObservedTimes) == 0 && !e.FirstSeen.IsZero() {
			e.ObservedTimes = []time.Time{e.FirstSeen.UTC()}
		}
		a.seen[key] = len(a.out)
		a.out = append(a.out, e)
	}
}

func (a *edgeAccumulator) edges() []connectivity.Edge {
	return a.out
}

type edgeScanFunc func(context.Context, int) ([]connectivity.Edge, error)
type edgeCommitFunc func([]connectivity.Edge)

type orderedEdgeScanStats struct {
	maxOutstanding int
	maxPending     int
}

type orderedEdgeScanResult struct {
	fileIdx int
	edges   []connectivity.Edge
	err     error
}

// runBoundedOrderedEdgeScans scans files concurrently while committing their
// results in file-index order. Dispatch is restricted to workerCount file
// indexes ahead of the commit frontier. Consequently, a slow early file cannot
// cause later per-file edge batches to accumulate without bound.
func runBoundedOrderedEdgeScans(
	ctx context.Context,
	totalFiles int,
	workerCount int,
	scan edgeScanFunc,
	commit edgeCommitFunc,
) (orderedEdgeScanStats, error) {
	var stats orderedEdgeScanStats
	if totalFiles == 0 {
		return stats, nil
	}
	if workerCount > totalFiles {
		workerCount = totalFiles
	}
	if workerCount < 1 {
		workerCount = 1
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	results := make(chan orderedEdgeScanResult, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-scanCtx.Done():
					return
				case fileIdx, ok := <-jobs:
					if !ok {
						return
					}
					edges, err := scan(scanCtx, fileIdx)
					select {
					case results <- orderedEdgeScanResult{fileIdx: fileIdx, edges: edges, err: err}:
					case <-scanCtx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	nextDispatch := 0
	nextCommit := 0
	pending := make(map[int][]connectivity.Edge, workerCount)
	jobsOpen := true
	closeJobs := func() {
		if jobsOpen {
			close(jobs)
			jobsOpen = false
		}
	}

	var firstErr error
	ctxDone := ctx.Done()
	stop := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
		cancel()
		closeJobs()
		pending = nil
		// The parent context remains permanently readable after cancellation.
		// Disable this select arm so the coordinator blocks on worker results
		// instead of spinning while workers shut down.
		ctxDone = nil
	}
	for results != nil {
		if firstErr == nil {
			select {
			case <-ctxDone:
				stop(ctx.Err())
			default:
			}
		}

		var (
			dispatch chan<- int
			fileIdx  int
		)
		if firstErr == nil && jobsOpen && nextDispatch < totalFiles && nextDispatch-nextCommit < workerCount {
			dispatch = jobs
			fileIdx = nextDispatch
		}

		select {
		case dispatch <- fileIdx:
			nextDispatch++
			outstanding := nextDispatch - nextCommit
			if outstanding > stats.maxOutstanding {
				stats.maxOutstanding = outstanding
			}
			if nextDispatch == totalFiles {
				closeJobs()
			}

		case result, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			if firstErr != nil {
				continue
			}
			if result.err != nil {
				stop(result.err)
				continue
			}

			pending[result.fileIdx] = result.edges
			if len(pending) > stats.maxPending {
				stats.maxPending = len(pending)
			}
			for {
				edges, exists := pending[nextCommit]
				if !exists {
					break
				}
				commit(edges)
				delete(pending, nextCommit)
				nextCommit++
			}

		case <-ctxDone:
			if firstErr == nil {
				stop(ctx.Err())
			}
		}
	}

	closeJobs()
	return stats, firstErr
}
