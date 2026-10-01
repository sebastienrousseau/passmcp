// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"os"
	"strings"
)

// BaseEnv is what a server gets when the caller names nothing.
//
// A program needs to be able to find its interpreter and its libraries, and
// an empty environment breaks almost everything for no security gain — PATH
// is not a secret. Everything that might be one is left out.
var BaseEnv = []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SystemRoot", "COMSPEC", "PATHEXT"}

// environment builds what the child will see.
func (c StdioConfig) environment() []string {
	if c.Env != nil {
		// An explicit Env is exactly what the caller asked for, including
		// an explicitly empty one -- plus whatever passmcp injects about
		// itself, which the caller is not choosing between.
		return inject(append([]string{}, c.Env...), c.Inject)
	}
	names := append(append([]string{}, BaseEnv...), c.PassEnv...)
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if v, ok := os.LookupEnv(n); ok {
			out = append(out, n+"="+v)
		}
	}
	// A non-nil empty slice, so os/exec does not fall back to inheriting
	// the caller's environment when nothing matched.
	return inject(out, c.Inject)
}

// inject appends passmcp's own variables, replacing any of the same name.
//
// Last-wins would be enough for os/exec, which takes the final assignment,
// but a duplicated name in a list somebody may read in a report is a
// second thing to explain.
func inject(env, extra []string) []string {
	if len(extra) == 0 {
		return env
	}
	names := make(map[string]bool, len(extra))
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names[k] = true
		}
	}
	out := make([]string, 0, len(env)+len(extra))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && names[k] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}
