// Package diagnostics provides opt-in process memory evidence for offline runs.
package diagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Environment is deliberately independent of topology YAML/CLI configuration.
const Environment = "PCAPTOOL_DIAGNOSTICS_DIR"

// Session owns a unique diagnostic directory. It never inspects pipeline data
// from its sampling goroutine. A nil Session is disabled and safe to call.
type Session struct {
	mu                sync.Mutex
	dir               string
	file              *os.File
	start, stageStart time.Time
	stage             string
	sequence          int
	err               error
	closed            bool
	stop, done        chan struct{}
	closeOnce         sync.Once
}

type sample struct {
	Time            time.Time         `json:"time"`
	Kind            string            `json:"kind"`
	Stage           string            `json:"stage"`
	PID             int               `json:"pid"`
	ElapsedMS       int64             `json:"elapsed_ms"`
	StageElapsedMS  int64             `json:"stage_elapsed_ms"`
	HeapAlloc       uint64            `json:"heap_alloc_bytes"`
	HeapInuse       uint64            `json:"heap_inuse_bytes"`
	HeapIdle        uint64            `json:"heap_idle_bytes"`
	HeapReleased    uint64            `json:"heap_released_bytes"`
	TotalAlloc      uint64            `json:"total_alloc_bytes"`
	HeapObjects     uint64            `json:"heap_objects"`
	Sys             uint64            `json:"go_sys_bytes"`
	NumGC           uint32            `json:"num_gc"`
	PauseTotalNS    uint64            `json:"gc_pause_total_ns"`
	Goroutines      int               `json:"goroutines"`
	ProcessKiB      map[string]uint64 `json:"process_kib,omitempty"`
	ProcessError    string            `json:"process_status_error,omitempty"`
	Counts          map[string]int    `json:"counts,omitempty"`
	Profile         string            `json:"heap_profile,omitempty"`
	PreviousStage   string            `json:"previous_stage,omitempty"`
	PreviousStageMS int64             `json:"previous_stage_ms,omitempty"`
}

// Start enables two-second samples when root is nonempty. No GC is forced and
// the runtime's allocation sampling rate is left unchanged.
func Start(root string) (*Session, error) {
	if root == "" {
		return nil, nil
	}
	return start(root, 2*time.Second)
}

func start(root string, interval time.Duration) (*Session, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("diagnostics directory: %w", err)
	}
	dir, err := os.MkdirTemp(root, fmt.Sprintf("run-%s-pid%d-", time.Now().UTC().Format("20060102T150405Z"), os.Getpid()))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "memory.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s := &Session{
		dir: dir, file: f, start: now, stageStart: now, stage: "startup",
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	build, _ := debug.ReadBuildInfo()
	err = json.NewEncoder(f).Encode(map[string]any{
		"kind": "metadata", "schema_version": 1, "pid": os.Getpid(),
		"go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0),
		"build": build, "sample_interval_ms": interval.Milliseconds(),
	})
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	s.Checkpoint("startup", nil, false)
	if s.err != nil {
		_ = f.Close()
		return nil, s.err
	}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.mu.Lock()
				s.writeSample("sample", nil, "", "", 0)
				s.mu.Unlock()
			}
		}
	}()
	return s, nil
}

// Directory returns the unique output directory, or empty when disabled.
func (s *Session) Directory() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Checkpoint samples before writing an optional heap profile, so an interrupted
// profile does not erase the last stage marker. Counts are synchronously encoded;
// callers must own the structures they measure. No packet/IP data is logged.
func (s *Session) Checkpoint(stage string, counts map[string]int, profile bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	previous, duration := s.stage, time.Since(s.stageStart).Milliseconds()
	s.stage, s.stageStart = stage, time.Now()
	s.sequence++
	name := ""
	if profile {
		name = fmt.Sprintf("heap-%03d.pprof", s.sequence)
	}
	s.writeSample("checkpoint", counts, name, previous, duration)
	if profile && s.err == nil {
		f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			err = errors.Join(pprof.WriteHeapProfile(f), f.Close())
		}
		if err != nil {
			s.err = fmt.Errorf("diagnostic heap profile %s: %w", name, err)
		}
	}
}

func (s *Session) writeSample(kind string, counts map[string]int, profile, previous string, previousMS int64) {
	if s.err != nil {
		return
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	proc, err := os.ReadFile("/proc/self/status")
	entry := sample{
		Time: time.Now().UTC(), Kind: kind, Stage: s.stage, PID: os.Getpid(),
		ElapsedMS:      time.Since(s.start).Milliseconds(),
		StageElapsedMS: time.Since(s.stageStart).Milliseconds(),
		HeapAlloc:      m.HeapAlloc, HeapInuse: m.HeapInuse,
		HeapIdle: m.HeapIdle, HeapReleased: m.HeapReleased,
		TotalAlloc: m.TotalAlloc, HeapObjects: m.HeapObjects, Sys: m.Sys,
		NumGC: m.NumGC, PauseTotalNS: m.PauseTotalNs,
		Goroutines: runtime.NumGoroutine(), Counts: counts, Profile: profile,
		PreviousStage: previous, PreviousStageMS: previousMS,
	}
	if err != nil {
		entry.ProcessError = err.Error()
	} else {
		entry.ProcessKiB = parseStatus(string(proc))
	}
	if err := json.NewEncoder(s.file).Encode(entry); err != nil {
		s.err = fmt.Errorf("diagnostic memory log: %w", err)
	}
}

func parseStatus(status string) map[string]uint64 {
	values := make(map[string]uint64, 3)
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "VmRSS" && key != "VmHWM" && key != "VmSwap" {
			continue
		}
		if n, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			values[key] = n
		}
	}
	return values
}

// Close stops and joins the sampler, closes the log and reports any diagnostic
// I/O failure. Later checkpoints are ignored; repeated Close calls are safe.
// Callers decide whether the underlying workload succeeded.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
		s.mu.Lock()
		defer s.mu.Unlock()
		s.err = errors.Join(s.err, s.file.Close())
		s.closed = true
	})
	return s.err
}
