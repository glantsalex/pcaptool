package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/progress"
)

type RunArtifactsManifest struct {
	RunID               string            `json:"run_id"`
	NetID               string            `json:"net_id"`
	RunDir              string            `json:"run_dir"`
	OutputRoot          string            `json:"output_root"`
	ReadDir             string            `json:"read_dir"`
	RunStartedAtUTC     string            `json:"run_started_at_utc"`
	PCAPFilesCount      int               `json:"pcap_files_count"`
	MainOutputFormat    string            `json:"main_output_format"`
	FirstPacketTSUTC    string            `json:"first_packet_ts_utc,omitempty"`
	FirstPacketPCAPFile string            `json:"first_packet_pcap_file,omitempty"`
	Files               map[string]string `json:"files"`
}

func writeRunArtifactsManifest(
	om *OutputManager,
	runStartedAt time.Time,
	readDir string,
	pcapFilesCount int,
	first dns.FirstPacketInfo,
	mainOutputFormat string,
	files map[string]string,
) (string, error) {
	path := om.Path("_run-artifacts.json")

	firstTS := ""
	if !first.Timestamp.IsZero() {
		firstTS = first.Timestamp.UTC().Format(time.RFC3339Nano)
	}

	cleanFiles := make(map[string]string, len(files))
	keys := make([]string, 0, len(files))
	for k, v := range files {
		if v == "" {
			continue
		}
		cleanFiles[k] = filepath.Clean(v)
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sortedFiles := make(map[string]string, len(cleanFiles))
	for _, k := range keys {
		sortedFiles[k] = cleanFiles[k]
	}

	manifest := RunArtifactsManifest{
		RunID:               om.RunID(),
		NetID:               om.NetID(),
		RunDir:              om.RunDir(),
		OutputRoot:          om.OutputRoot(),
		ReadDir:             filepath.Clean(readDir),
		RunStartedAtUTC:     runStartedAt.UTC().Format(time.RFC3339Nano),
		PCAPFilesCount:      pcapFilesCount,
		MainOutputFormat:    mainOutputFormat,
		FirstPacketTSUTC:    firstTS,
		FirstPacketPCAPFile: first.PCAPFile,
		Files:               sortedFiles,
	}

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create run artifacts manifest %q: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		return "", fmt.Errorf("encode run artifacts manifest %q: %w", path, err)
	}
	return path, nil
}

func runPostHooks(ctx context.Context, om *OutputManager, manifestPath string, hooks []string) error {
	for i, hook := range hooks {
		progress.SetStage(fmt.Sprintf("Post-hook %d/%d...", i+1, len(hooks)))

		cmd := exec.CommandContext(ctx, "sh", "-c", hook)
		cmd.Dir = om.RunDir()
		cmd.Env = append(os.Environ(),
			"PCAPTOOL_MANIFEST="+manifestPath,
			"PCAPTOOL_RUN_DIR="+om.RunDir(),
			"PCAPTOOL_RUN_ID="+om.RunID(),
			"PCAPTOOL_NET_ID="+om.NetID(),
			"PCAPTOOL_OUTPUT_ROOT="+om.OutputRoot(),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("post-hook %d failed: %w", i+1, err)
		}
	}
	return nil
}
