// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// With no home directory the default config used to be
// .config/passmcp/config.json relative to the working directory. A
// repository can carry that file, and it would set the options of a run
// started inside it. Loading must refuse instead.
func TestLoadOptionalWithoutAHomeDirectoryReadsNothing(t *testing.T) {
	cwd := t.TempDir()
	planted := filepath.Join(cwd, ".config", "passmcp", "config.json")
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte(`{"defaults":{"rps":1000}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	t.Setenv("PASSMCP_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this platform reports a home directory without the variables")
	}

	f, path, err := LoadOptional("")
	if err == nil {
		t.Errorf("LoadOptional read %s (%d defaults) with no home directory", path, len(f.Defaults))
	}
}
