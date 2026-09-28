// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build darwin

package canary

import (
	"os"
	"syscall"
	"time"
)

// accessTime reads the last-access time of a file.
//
// Measured on macOS during this work: APFS does not move it on an
// ordinary read, so the witness built on this is expected to report
// itself unusable here rather than report a clean result.
func accessTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec), true
}
