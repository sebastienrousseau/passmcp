// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package creds

import "os"

// insecureMode reports whether a token store is readable or writable by
// anyone but its owner.
func insecureMode(m os.FileMode) bool { return m.Perm()&0o077 != 0 }
