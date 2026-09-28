// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build linux

package canary

import (
	"os"
	"syscall"
	"time"
)

// accessTime reads the last-access time of a file.
//
// Whether it moves depends on the mount: `relatime`, the usual default,
// records a read when the recorded time is older than a day, which is why
// the decoys are backdated well past that. `noatime` records nothing, and
// the probe in Seed is what tells the two apart.
func accessTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(st.Atim.Sec, st.Atim.Nsec), true
}
