// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !linux && !darwin

package engine

// kernelRelease is unknown where there is no portable way to read it.
func kernelRelease() string { return "" }
