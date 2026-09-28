// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	info := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Path: "satellion.com/passmcp", Version: v}}, true
		}
	}
	none := func() (*debug.BuildInfo, bool) { return nil, false }
	for _, tc := range []struct {
		name, injected string
		read           func() (*debug.BuildInfo, bool)
		want           string
	}{
		{"ldflags wins over module version", "0.0.6", info("v0.0.5"), "0.0.6"},
		{"go install at a tag", "dev", info("v0.0.5"), "0.0.5"},
		{"local build pseudo-version", "dev", info("v0.0.6-0.20260924201500-044433a1b2c3+dirty"), "0.0.6-0.20260924201500-044433a1b2c3+dirty"},
		{"toolchain knew nothing", "dev", info("(devel)"), "dev"},
		{"empty module version", "dev", info(""), "dev"},
		{"no build info", "dev", none, "dev"},
		{"nil build info", "dev", func() (*debug.BuildInfo, bool) { return nil, true }, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.injected, tc.read); got != tc.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tc.injected, got, tc.want)
			}
		})
	}
}
