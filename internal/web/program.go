// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import "satellion.com/passmcp/internal/engine"

// startsProgram reports whether running spec would start a program on this
// machine: a stdio target, or a stdio server in the client configuration,
// which the catalog phase starts to list its tools.
func startsProgram(spec engine.RunSpec) bool {
	if spec.Target.Stdio() {
		return true
	}
	if spec.ClientConfig == nil {
		return false
	}
	for _, p := range spec.ClientConfig.Servers {
		if p.Stdio() {
			return true
		}
	}
	return false
}
