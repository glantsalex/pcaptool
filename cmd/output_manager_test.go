package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewOutputManagerForRunUsesPCAPDateAndRunStartUTC(t *testing.T) {
	root := t.TempDir()
	pcapTimestamp := time.Date(2026, 6, 23, 23, 30, 0, 0, time.FixedZone("west", -2*60*60))
	runStartedAt := time.Date(2026, 7, 2, 14, 35, 22, 0, time.UTC)

	om, err := NewOutputManagerForRun("404163-1", root, pcapTimestamp, runStartedAt)
	if err != nil {
		t.Fatalf("NewOutputManagerForRun: %v", err)
	}
	want := filepath.Join(root, "404163-1", "pcap-date-2026-06-24", "run-20260702T143522Z")
	if om.RunDir() != want {
		t.Fatalf("RunDir = %q, want %q", om.RunDir(), want)
	}
	if om.RunID() != "run-20260702T143522Z" || om.PCAPDate() != "2026-06-24" {
		t.Fatalf("identity = RunID %q PCAPDate %q", om.RunID(), om.PCAPDate())
	}
	if strings.Contains(om.RunDir(), "=") {
		t.Fatalf("RunDir contains rejected equals-style segment: %q", om.RunDir())
	}
}

func TestNewOutputManagerForRunFixedRequestedExample(t *testing.T) {
	root := t.TempDir()
	om, err := NewOutputManagerForRun(
		"404163-1",
		root,
		time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 2, 14, 35, 22, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("NewOutputManagerForRun: %v", err)
	}
	want := filepath.Join(root, "404163-1", "pcap-date-2026-06-23", "run-20260702T143522Z")
	if om.RunDir() != want {
		t.Fatalf("RunDir = %q, want %q", om.RunDir(), want)
	}
}

func TestNewOutputManagerForRunUnknownPCAPDate(t *testing.T) {
	root := t.TempDir()
	om, err := NewOutputManagerForRun("net", root, time.Time{}, time.Date(2026, 7, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewOutputManagerForRun: %v", err)
	}
	if om.PCAPDate() != "unknown" {
		t.Fatalf("PCAPDate = %q, want unknown", om.PCAPDate())
	}
	want := filepath.Join(root, "net", "pcap-date-unknown", "run-20260702T010203Z")
	if om.RunDir() != want {
		t.Fatalf("RunDir = %q, want %q", om.RunDir(), want)
	}
}

func TestNewOutputManagerForRunZeroRunStartUsesCurrentUTCShape(t *testing.T) {
	om, err := NewOutputManagerForRun("net", t.TempDir(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewOutputManagerForRun: %v", err)
	}
	if !strings.HasPrefix(om.RunID(), "run-") {
		t.Fatalf("RunID = %q, want run-*", om.RunID())
	}
	if _, err := time.Parse("20060102T150405Z", strings.TrimPrefix(om.RunID(), "run-")); err != nil {
		t.Fatalf("RunID = %q is not UTC run timestamp: %v", om.RunID(), err)
	}
	if om.PCAPDate() != "unknown" {
		t.Fatalf("PCAPDate = %q, want unknown", om.PCAPDate())
	}
}

func TestNewOutputManagerForRunRejectsEqualsNetID(t *testing.T) {
	for _, netID := range []string{"=net", "net=value"} {
		if _, err := NewOutputManagerForRun(netID, t.TempDir(), time.Time{}, time.Now()); err == nil {
			t.Fatalf("NewOutputManagerForRun(%q) error = nil", netID)
		}
	}
}

func TestNewOutputManagerForRunRejectsCollision(t *testing.T) {
	root := t.TempDir()
	pcapTimestamp := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	runStartedAt := time.Date(2026, 7, 2, 14, 35, 22, 0, time.UTC)
	if _, err := NewOutputManagerForRun("net", root, pcapTimestamp, runStartedAt); err != nil {
		t.Fatalf("first NewOutputManagerForRun: %v", err)
	}
	if _, err := NewOutputManagerForRun("net", root, pcapTimestamp, runStartedAt); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestNewOutputManagerResolvesRelativeOutputRootToAbsolute(t *testing.T) {
	cwd := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	om, err := NewOutputManager("net", "pcaptool_output")
	if err != nil {
		t.Fatalf("NewOutputManager: %v", err)
	}

	if !filepath.IsAbs(om.OutputRoot()) {
		t.Fatalf("expected absolute output root, got %q", om.OutputRoot())
	}
	if !filepath.IsAbs(om.RunDir()) {
		t.Fatalf("expected absolute run dir, got %q", om.RunDir())
	}
	if !strings.HasPrefix(om.RunDir(), om.OutputRoot()) {
		t.Fatalf("run dir %q should be under output root %q", om.RunDir(), om.OutputRoot())
	}
}

func TestNewOutputManagerForRunPreservesAbsoluteOutputRoot(t *testing.T) {
	root := t.TempDir()
	om, err := NewOutputManagerForRun("net", root, time.Time{}, time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewOutputManagerForRun: %v", err)
	}
	if om.OutputRoot() != root {
		t.Fatalf("OutputRoot = %q, want %q", om.OutputRoot(), root)
	}
}
