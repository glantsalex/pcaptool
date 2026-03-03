// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	mu          sync.Mutex
	stage       string
	globalStart time.Time
)

// SetStage sets the current high-level stage and prints it.
// The first call also initializes the global timer.
func SetStage(s string) {
	mu.Lock()
	defer mu.Unlock()

	if globalStart.IsZero() {
		globalStart = time.Now()
	}

	stage = s
	fmt.Fprintf(os.Stderr, "\n[stage] %s\n", s)
}

// UpdateBar renders a single-line progress bar:
// current/total, percentage, extra label, and elapsed time.
func UpdateBar(current, total int, extra string) {

	if os.Getenv("PCAPTOOL_NO_PROGRESS") == "1" {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if total <= 0 {
		return
	}

	ratio := float64(current) / float64(total)
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	const barLen = 30
	filled := int(ratio * barLen)
	if filled > barLen {
		filled = barLen
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barLen-filled)
	percent := int(ratio*100 + 0.5)

	elapsedStr := ""
	if !globalStart.IsZero() {
		elapsed := time.Since(globalStart)
		elapsedStr = formatDuration(elapsed)
	}

	// \r keeps it on one line; newline when we reach total.
	fmt.Fprintf(os.Stderr, "\r[%s] [%s] %3d%% %d/%d %s | %s",
		stage, bar, percent, current, total, extra, elapsedStr)

	if current >= total {
		fmt.Fprintln(os.Stderr)
	}
}

// Optional file-level helpers (keep if you like the extra logging).
func FileStarted(path string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(os.Stderr, "[pcap] starting %s\n", path)
}

func FileDone(path string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(os.Stderr, "[pcap] done %s\n", path)
}

// Done prints a final message with total elapsed time.
func Done(msg string) {
	mu.Lock()
	defer mu.Unlock()

	elapsedStr := ""
	if !globalStart.IsZero() {
		elapsedStr = formatDuration(time.Since(globalStart))
	}
	if elapsedStr != "" {
		fmt.Fprintf(os.Stderr, "\n[done] %s (elapsed %s)\n", msg, elapsedStr)
	} else {
		fmt.Fprintf(os.Stderr, "\n[done] %s\n", msg)
	}
}

// formatDuration -> "HH:MM:SS"
func formatDuration(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 0 {
		sec = 0
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}
