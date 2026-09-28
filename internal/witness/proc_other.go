// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !linux

package witness

// Take reports that this platform has no /proc to read.
func Take(int) (Snapshot, error) { return Snapshot{}, ErrUnsupported }

// RSS reports that this platform has no /proc to read.
func RSS(int) (int64, error) { return 0, ErrUnsupported }
