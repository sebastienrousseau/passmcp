// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package creds

import "os"

// insecureMode is always false on Windows, because the mode it would test
// does not exist there.
//
// Windows has no Unix permission bits. Go synthesises a mode for every file
// it stats — 0666 for a regular file, 0444 when the read-only attribute is
// set — from the DOS attributes alone, and that value says nothing about
// who can read the file. Applying the Unix test to it rejects every store
// on the platform, which is what it did: passmcp could not read or write a
// token on Windows at all.
//
// Access on Windows is governed by the ACL, and the store lives under the
// user's own profile directory, which inherits an ACL granting that user
// and the administrators group. Reading it as another unprivileged user is
// already denied by the filesystem. Auditing that ACL properly would mean
// calling into the Win32 security API, and passmcp carries no cgo and no
// dependency that would do it; claiming a check passmcp does not perform
// would be worse than declining to perform one.
func insecureMode(os.FileMode) bool { return false }
