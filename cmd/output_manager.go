// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var netIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// OutputManager owns all output path decisions for a single pcaptool run.
//
// Layout:
//
//	<output-root>/<net-id>/<YYYY-MM-DD-HH-mm-ss>/...
//
// Notes:
//   - Timestamps are UTC.
//   - Directory collisions are treated as an error (for forensic repeatability).
type OutputManager struct {
	outputRoot string
	netID      string
	runID      string
	netDir     string
	runDir     string
}

// NewOutputManager creates (if needed) the output root/network directory and a unique per-run directory.
// Relative outputRoot is resolved against the current working directory.
func NewOutputManager(netID, outputRoot string) (*OutputManager, error) {
	if strings.TrimSpace(netID) == "" {
		return nil, fmt.Errorf("--net-id must be non-empty")
	}
	if !netIDRe.MatchString(netID) {
		return nil, fmt.Errorf("--net-id %q is invalid: use letters/digits and ._- only", netID)
	}
	outputRoot = strings.TrimSpace(outputRoot)
	if outputRoot == "" {
		outputRoot = "pcaptool_output"
	}
	rootDir, err := filepath.Abs(filepath.Clean(outputRoot))
	if err != nil {
		return nil, fmt.Errorf("resolve output root %q: %w", outputRoot, err)
	}

	runID := time.Now().UTC().Format("2006-01-02-15-04-05")
	netDir := filepath.Join(rootDir, filepath.Clean(netID))
	runDir := filepath.Join(netDir, runID)

	if err := os.MkdirAll(netDir, 0o755); err != nil {
		return nil, fmt.Errorf("create net output dir %q: %w", netDir, err)
	}
	if err := os.Mkdir(runDir, 0o755); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("run output dir already exists: %q", runDir)
		}
		return nil, fmt.Errorf("create run output dir %q: %w", runDir, err)
	}

	return &OutputManager{
		outputRoot: rootDir,
		netID:      netID,
		runID:      runID,
		netDir:     netDir,
		runDir:     runDir,
	}, nil
}

// OutputRoot returns the configured output root directory path.
func (m *OutputManager) OutputRoot() string { return m.outputRoot }

// NetID returns the network identifier.
func (m *OutputManager) NetID() string { return m.netID }

// RunID returns the per-run timestamp ID.
func (m *OutputManager) RunID() string { return m.runID }

// NetDir returns the network directory path under the output root.
func (m *OutputManager) NetDir() string { return m.netDir }

// RunDir returns the per-run directory path under the output root.
func (m *OutputManager) RunDir() string { return m.runDir }

// Path returns a path under the run directory. The file is not created.
func (m *OutputManager) Path(name string) string {
	name = filepath.Clean(name)
	return filepath.Join(m.runDir, name)
}

// Create creates a file under the run directory and returns an opened handle.
// Parent directories are created if needed.
func (m *OutputManager) Create(name string) (*os.File, error) {
	p := m.Path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, fmt.Errorf("create output dir for %q: %w", p, err)
	}
	f, err := os.Create(p)
	if err != nil {
		return nil, fmt.Errorf("create output file %q: %w", p, err)
	}
	return f, nil
}

// ResolvePath resolves a user-provided path into a concrete filesystem path.
//
// Behavior:
//   - If userPath is empty, it returns an empty string.
//   - If userPath is absolute, it is returned as-is.
//   - Otherwise, it is placed under the current run directory.
//
// This lets flags like --export-csv behave consistently with the per-run output layout.
func (m *OutputManager) ResolvePath(userPath string) string {
	userPath = strings.TrimSpace(userPath)
	if userPath == "" {
		return ""
	}
	if filepath.IsAbs(userPath) {
		return userPath
	}
	return m.Path(userPath)
}
