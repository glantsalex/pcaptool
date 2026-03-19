package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
