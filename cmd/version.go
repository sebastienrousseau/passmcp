// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"runtime/debug"
	"strings"
)

func init() {
	Version = resolveVersion(Version, debug.ReadBuildInfo)
}

// resolveVersion returns the version passmcp reports, and therefore the one
// every attestation records as its instrument.
//
// A version injected through -ldflags wins: it is what the release
// pipeline stamps. Without one, the module version the Go toolchain embeds
// is used, so `go install .../cmd/passmcp@v0.0.1` reports 0.0.1 rather than
// "dev" — the documented install path for CI, whose attestations would
// otherwise name an instrument nobody can reproduce. A local build of a
// checkout carries a pseudo-version, which names the commit and is still
// more honest than "dev". "(devel)" and an empty version mean the
// toolchain knew nothing, and "dev" stays.
func resolveVersion(injected string, read func() (*debug.BuildInfo, bool)) string {
	if injected != "dev" {
		return injected
	}
	info, ok := read()
	if !ok || info == nil {
		return injected
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return injected
	}
	return strings.TrimPrefix(v, "v")
}
