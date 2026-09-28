// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build darwin

package engine

import "syscall"

// kernelRelease is the running kernel's release, as uname -r prints it.
func kernelRelease() string {
	v, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return ""
	}
	return v
}
