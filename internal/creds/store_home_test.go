// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"os"
	"testing"
)

// unsetHome leaves the process with no home directory and no
// XDG_CONFIG_HOME, on every platform os.UserHomeDir reads.
func unsetHome(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this platform reports a home directory without the variables")
	}
}

// With no home directory the store used to fall back to
// .config/passmcp/tokens.json relative to the working directory, which is
// often a repository: a refresh token one `git add .` from being
// published. It must refuse instead and write nothing.
func TestStoreWithoutAHomeDirectoryWritesNothing(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	unsetHome(t)

	if err := (&Store{}).Put(StoredToken{Endpoint: "e", AccessToken: "a", RefreshToken: "r"}); err == nil {
		t.Error("Put succeeded with no home directory to keep the store in")
	}
	if _, err := (&Store{}).Get("e"); err == nil {
		t.Error("Get read a store with no home directory to find it in")
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Errorf("the working directory gained %d entries; the first is %s", len(entries), entries[0].Name())
	}
}
