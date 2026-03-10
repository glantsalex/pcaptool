package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
)

func TestWriteRunArtifactsManifest(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "net", "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir run dir: %v", err)
	}

	om := &OutputManager{
		outputRoot: root,
		netID:      "net",
		runID:      "run",
		netDir:     filepath.Join(root, "net"),
		runDir:     runDir,
	}

	manifestPath, err := writeRunArtifactsManifest(
		om,
		time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC),
		"/tmp/in",
		3,
		dns.FirstPacketInfo{
			Timestamp: time.Date(2026, 3, 10, 9, 59, 0, 0, time.UTC),
			PCAPFile:  "a.pcap",
		},
		"table",
		map[string]string{
			"service_endpoints": filepath.Join(runDir, "service-endpoints.txt"),
			"main_output":       filepath.Join(runDir, "dns-table.txt"),
		},
	)
	if err != nil {
		t.Fatalf("writeRunArtifactsManifest: %v", err)
	}

	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	var got RunArtifactsManifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if got.RunID != "run" || got.NetID != "net" {
		t.Fatalf("unexpected manifest identity: %+v", got)
	}
	if got.Files["main_output"] == "" || got.Files["service_endpoints"] == "" {
		t.Fatalf("expected file entries in manifest, got %+v", got.Files)
	}
}

func TestRunPostHooks(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "net", "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir run dir: %v", err)
	}
	manifestPath := filepath.Join(runDir, "_run-artifacts.json")
	if err := os.WriteFile(manifestPath, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	om := &OutputManager{
		outputRoot: root,
		netID:      "net",
		runID:      "run",
		netDir:     filepath.Join(root, "net"),
		runDir:     runDir,
	}

	target := filepath.Join(runDir, "hook.out")
	hook := "printf '%s|%s|%s' \"$PCAPTOOL_NET_ID\" \"$PCAPTOOL_RUN_ID\" \"$PCAPTOOL_MANIFEST\" > " + filepath.Base(target)
	if err := runPostHooks(context.Background(), om, manifestPath, []string{hook}); err != nil {
		t.Fatalf("runPostHooks: %v", err)
	}

	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read hook output: %v", err)
	}
	got := string(b)
	want := "net|run|" + manifestPath
	if got != want {
		t.Fatalf("unexpected hook output %q, want %q", got, want)
	}
}
