package diagnostics

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDisabledAndInvalidDestination(t *testing.T) {
	s, err := Start("")
	if err != nil || s != nil {
		t.Fatalf("disabled: %v %v", s, err)
	}
	s.Checkpoint("ignored", nil, true)
	if s.Directory() != "" || s.Close() != nil {
		t.Fatal("nil session not disabled")
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(path); err == nil {
		t.Fatal("expected initialization error")
	}
}

func TestSamplesProfilesAndLifecycle(t *testing.T) {
	root := t.TempDir()
	s, err := start(root, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	second, err := Start(root)
	if err != nil {
		t.Fatal(err)
	}
	if second.Directory() == s.Directory() {
		t.Fatal("runs share directory")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	s.Checkpoint("before_write", map[string]int{"records_len": 23, "records_cap": 32}, true)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Checkpoint("parallel", nil, false) }()
	}
	wg.Wait()
	logPath := filepath.Join(s.Directory(), "memory.jsonl")
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"kind":"sample"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic sampler did not run")
		}
		time.Sleep(time.Millisecond)
	}
	s.Checkpoint("run_completed", nil, false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(logPath)
	time.Sleep(5 * time.Millisecond)
	after, _ := os.Stat(logPath)
	if before.Size() != after.Size() {
		t.Fatal("sampler continued after Close")
	}
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	foundProfile, foundCounts, foundSample := false, false, false
	for scan.Scan() {
		var row sample
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row.Kind == "metadata" {
			continue
		}
		if row.PID != os.Getpid() || row.HeapInuse == 0 || row.Time.IsZero() {
			t.Fatalf("incomplete sample: %+v", row)
		}
		if row.Kind == "sample" {
			foundSample = true
		}
		if row.Stage == "before_write" && row.Counts["records_len"] == 23 && row.Counts["records_cap"] == 32 {
			foundCounts = true
		}
		if row.Profile != "" {
			profilePath := filepath.Join(s.Directory(), row.Profile)
			info, err := os.Stat(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatal("profile permissions too broad")
			}
			pf, err := os.Open(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(pf)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(gz)
			if err != nil || len(body) == 0 {
				t.Fatalf("invalid profile: %v", err)
			}
			_ = gz.Close()
			_ = pf.Close()
			foundProfile = true
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundProfile || !foundCounts || !foundSample {
		t.Fatal("missing profile, counts, or sample")
	}
}

func TestWriteErrorsAreReported(t *testing.T) {
	s, err := Start(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_ = s.file.Close()
	s.mu.Unlock()
	s.Checkpoint("unwritable", nil, false)
	if err := s.Close(); err == nil {
		t.Fatal("missing write error")
	}
}

func TestParseLinuxStatus(t *testing.T) {
	got := parseStatus("VmRSS: 1024 kB\nVmHWM: 2048 kB\nVmSwap: 0 kB\nVmSize: 999 kB\nOther: secret\nVmRSS: invalid kB\n")
	if len(got) != 3 || got["VmRSS"] != 1024 || got["VmHWM"] != 2048 || got["VmSwap"] != 0 {
		t.Fatalf("bad process memory: %v", got)
	}
}

func TestProfileCreationFailure(t *testing.T) {
	s, err := Start(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Startup is checkpoint 1. An existing profile must never be overwritten.
	path := filepath.Join(s.Directory(), "heap-002.pprof")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Checkpoint("profile_failure", nil, true)
	if err := s.Close(); err == nil || !strings.Contains(err.Error(), "heap-002.pprof") {
		t.Fatalf("missing profile failure: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatal("existing profile changed")
	}
	s.Checkpoint("after_close", nil, true)
}
