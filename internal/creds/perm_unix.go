// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package creds

import "os"

// insecureMode reports whether a token store is readable or writable by
// anyone but its owner.
func insecureMode(m os.FileMode) bool { return m.Perm()&0o077 != 0 }

// checkStoreAccess refuses a store whose mode lets anyone but its owner
// read or write it.
func checkStoreAccess(path string, info os.FileInfo) error {
	if insecureMode(info.Mode()) {
		return &ErrInsecurePermissions{Path: path, Mode: info.Mode()}
	}
	return nil
}

// restrictFile makes a new store file readable and writable by its owner
// only.
func restrictFile(f *os.File) error { return f.Chmod(0o600) }
