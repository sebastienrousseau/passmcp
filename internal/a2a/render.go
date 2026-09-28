// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"fmt"
	"io"
	"strings"

	"satellion.com/passmcp/internal/probe"
)

// WriteText renders a result for a terminal.
func WriteText(w io.Writer, r *Result) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("passmcp a2a check %s\n", r.Target)
	if r.Agent.Name != "" {
		p("agent  %s %s (A2A %s)\n", r.Agent.Name, r.Agent.Version, dash(r.Agent.ProtocolVersion))
	}
	p("card   %s\n\n", r.CardURL)
	for _, f := range r.Findings {
		p("%-5s %-22s %s\n", mark(f.Status), f.ID, f.Detail)
		if len(f.Evidence) > 0 {
			p("      %-22s evidence: %s\n", "", strings.Join(f.Evidence, ", "))
		}
		if f.Advice != "" {
			p("      %-22s fix: %s\n", "", f.Advice)
		}
	}
	if extra := len(r.SchemaErrors); extra > 5 {
		p("\nschema errors (%d):\n", extra)
		for _, e := range r.SchemaErrors {
			p("  %s\n", e)
		}
	}
}

func mark(st probe.Status) string {
	switch st {
	case probe.Pass:
		return "ok"
	case probe.Fail:
		return "FAIL"
	case probe.Warn:
		return "warn"
	case probe.Skip:
		return "skip"
	}
	return "info"
}

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}
