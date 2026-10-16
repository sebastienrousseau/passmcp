// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"satellion.com/passmcp/transport"
)

// On Windows the home directory is not HOME. A server started without
// USERPROFILE or APPDATA cannot find its own configuration, and npm, which
// most stdio servers are launched through, cannot find its cache. None of
// these variables is a secret.
func TestBaseEnvCarriesTheWindowsHomeVariables(t *testing.T) {
	for _, name := range []string{
		"USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "SystemDrive", "ProgramData",
	} {
		if !slices.Contains(transport.BaseEnv, name) {
			t.Errorf("BaseEnv lacks %s", name)
		}
	}
}

// docs/stdio.md states the base environment to the operator. It is written
// by hand, so it is held to BaseEnv here.
func TestStdioDocListsBaseEnv(t *testing.T) {
	b, err := os.ReadFile("../docs/stdio.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(transport.BaseEnv, " "); !strings.Contains(string(b), "\n"+want+"\n") {
		t.Errorf("docs/stdio.md does not list the base environment as BaseEnv has it:\n%s", want)
	}
}
