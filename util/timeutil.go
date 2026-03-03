// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package util

import "time"

// FormatOutputTimestamp returns YYYY-MM-DD-HH-mm for filenames in UTC.
func FormatOutputTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02-15-04")
}
