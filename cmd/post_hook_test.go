package cmd

import (
	"bytes"
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
	hook := "printf '%s' \"$PCAPTOOL_MANIFEST\" > " + filepath.Base(target)
	if err := runPostHooks(context.Background(), om, manifestPath, []string{hook}); err != nil {
		t.Fatalf("runPostHooks: %v", err)
	}

	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read hook output: %v", err)
	}
	got := string(b)
	want := manifestPath
	if got != want {
		t.Fatalf("unexpected hook output %q, want %q", got, want)
	}
}

func TestDebugPrintPostHook(t *testing.T) {
	var buf bytes.Buffer

	debugPrintPostHook(
		&buf,
		1,
		2,
		"/opt/hooks/push-bq --mode append",
		"/tmp/run",
		[]string{
			"PCAPTOOL_MANIFEST=/tmp/run/_run-artifacts.json",
		},
	)

	got := buf.String()
	for _, want := range []string{
		"[pcaptool debug] post-hook 1/2",
		`cmd: "/opt/hooks/push-bq --mode append"`,
		`cwd: "/tmp/run"`,
		"env: PCAPTOOL_MANIFEST=/tmp/run/_run-artifacts.json",
	} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("debug output missing %q in %q", want, got)
		}
	}
}

func TestCopyFile(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "a", "manifest.json")
	dst := filepath.Join(root, "b", "copied.json")

	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir src dir: %v", err)
	}
	want := []byte(`{"ok":true}`)
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copied contents = %q, want %q", got, want)
	}
}
