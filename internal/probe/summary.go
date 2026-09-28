// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"strings"
	"time"
)

// summarize writes the one-line outcome of a phase in plain language, for
// the phase list and the executive overview. It states what was found,
// not what was checked.
func summarize(name string, s *Session, pr PhaseResult) string {
	t := tallyFindings(pr)
	// A stdio run's first and last phases look at a process rather than at
	// a network, so their summaries describe one. Falling through to the
	// HTTP wording produced "Reachable, plain HTTP on this machine" for a
	// server that was never reached over anything.
	if s.overStdio() {
		if out, ok := summarizeStdio(name, t); ok {
			return out
		}
	}

	switch name {
	case "net":
		return summarizeNet(t)
	case "discovery":
		return summarizeDiscovery(s, t)
	case "auth":
		return summarizeAuth(s, pr, t)
	case "handshake":
		return summarizeHandshake(s, t)
	case "protocol":
		if x := t.improve(); x != "" {
			return "Mostly conformant · " + x
		}
		return "Conformant on every edge case tested"
	case "catalog":
		return summarizeCatalog(s, t)
	case "execution":
		return summarizeExecution(s, t)
	case "performance":
		return summarizePerformance(s)
	case "resilience":
		return summarizeResilience(s, pr, t)
	}
	if x := t.improve(); x != "" {
		return x
	}
	return "Passed"
}

// phaseTally is what summarize needs from a phase's findings: each finding
// by id, and how many failed or warned.
type phaseTally struct {
	by           map[string]Finding
	fails, warns int
}

// tallyFindings indexes a phase's findings and counts its failures and
// warnings.
func tallyFindings(pr PhaseResult) phaseTally {
	t := phaseTally{by: map[string]Finding{}}
	for _, f := range pr.Findings {
		t.by[f.ID] = f
		switch f.Status {
		case Fail:
			t.fails++
		case Warn:
			t.warns++
		}
	}
	return t
}

// failed reports whether the finding with this id is present and failed.
func (t phaseTally) failed(id string) bool {
	f, ok := t.by[id]
	return ok && f.Status == Fail
}

// improve says how many issues and things to improve the phase found, or
// nothing when it found neither.
func (t phaseTally) improve() string {
	switch {
	case t.fails > 0 && t.warns > 0:
		return fmt.Sprintf("%s, %s", plural(t.fails, "issue"), plural(t.warns, "thing to improve", "things to improve"))
	case t.fails > 0:
		return plural(t.fails, "issue")
	case t.warns > 0:
		return plural(t.warns, "thing to improve", "things to improve")
	}
	return ""
}

// withImprove appends the improve note to out when there is one.
func (t phaseTally) withImprove(out string) string {
	if x := t.improve(); x != "" {
		out += " · " + x
	}
	return out
}

// summarizeStdio words the phases that look at a process rather than a
// network on a stdio run. ok is false for every other phase, which keeps
// the HTTP wording.
func summarizeStdio(name string, t phaseTally) (string, bool) {
	switch name {
	case "net":
		if t.failed("stdio.process") {
			return "The server exited before it was asked anything", true
		}
		return "Running as a child process", true
	case "resilience":
		if t.failed("stdio.alive") {
			return "The server died during the run", true
		}
		if t.failed("stdio.stdout_clean") {
			return "Writes to stdout that are not MCP messages", true
		}
		return "Survived the run with a clean transport", true
	}
	return "", false
}

// summarizeNet words the network phase: the first layer that failed, or
// how the server was reached.
func summarizeNet(t phaseTally) string {
	if t.failed("net.dns") {
		return "Hostname does not resolve"
	}
	if t.failed("net.tcp") {
		return "Not reachable"
	}
	if t.failed("net.tls") {
		return "TLS handshake fails"
	}
	if f, ok := t.by["net.tls"]; ok {
		out := "Reachable over " + firstWords(f.Detail, 2)
		if c, ok := t.by["net.tls.cert"]; ok && c.Status != Pass {
			out += ", certificate needs attention"
		}
		return out
	}
	if t.failed("net.scheme") {
		return "Reachable, but over plain HTTP"
	}
	return "Reachable, plain HTTP on this machine"
}

// summarizeDiscovery words the discovery phase: whether the server
// answered, and whether and where it wants authorization.
func summarizeDiscovery(s *Session, t phaseTally) string {
	if !s.Reached {
		return "Server did not answer"
	}
	if !s.RequiresAuth {
		return "Open server, no credentials required"
	}
	if s.Discovery != nil && s.Discovery.Server != nil {
		return t.withImprove("Protected, authorization via " + hostOf(s.Discovery.Server.Issuer))
	}
	return "Protected, but the authorization server could not be found"
}

// summarizeAuth words the auth phase: skipped, failed, or authorized and
// for how long.
func summarizeAuth(s *Session, pr PhaseResult, t phaseTally) string {
	if pr.Status == Skip {
		return "Not needed"
	}
	if t.fails > 0 {
		if t.failed("auth.rejects_garbage") {
			return "Accepts invalid tokens"
		}
		if f, ok := t.by["auth.token"]; ok {
			return "No usable credentials: " + firstSentence(f.Detail)
		}
	}
	if s.Token != nil {
		out := "Authorized"
		if !s.Token.Expiry.IsZero() {
			out += fmt.Sprintf(", token valid for %s", time.Until(s.Token.Expiry).Round(time.Minute))
		}
		return t.withImprove(out)
	}
	return "Credentials accepted"
}

// summarizeHandshake words the handshake phase: the server and protocol it
// agreed, or why it did not.
func summarizeHandshake(s *Session, t phaseTally) string {
	if s.Init == nil {
		if f, ok := t.by["handshake.initialize"]; ok {
			return "Rejected: " + firstSentence(f.Detail)
		}
		return "Failed"
	}
	out := fmt.Sprintf("%s %s, protocol %s", s.Init.ServerInfo.Name, s.Init.ServerInfo.Version, s.Init.ProtocolVersion)
	return strings.TrimSpace(t.withImprove(out))
}

// summarizeCatalog words the catalog phase: what the server offers an
// agent.
func summarizeCatalog(s *Session, t phaseTally) string {
	parts := []string{}
	if n := len(s.Tools); n > 0 {
		parts = append(parts, plural(n, "tool"))
	}
	if n := len(s.Resources); n > 0 {
		parts = append(parts, plural(n, "resource"))
	}
	if n := len(s.Prompts); n > 0 {
		parts = append(parts, plural(n, "prompt"))
	}
	if len(parts) == 0 {
		return "Nothing for an agent to use"
	}
	return t.withImprove(strings.Join(parts, ", "))
}

// summarizeExecution words the execution phase: how many of the tools
// that ran did so cleanly.
func summarizeExecution(s *Session, t phaseTally) string {
	ran, ok := 0, 0
	for _, r := range s.ToolResults {
		if r.Executed {
			ran++
			if r.OK {
				ok++
			}
		}
	}
	switch {
	case len(s.Tools) == 0 && len(s.Resources) == 0:
		return "Nothing to run"
	case ran == 0:
		return "No tool was safe to run without opting in"
	}
	return t.withImprove(fmt.Sprintf("%d of %d tools ran cleanly", ok, ran))
}

// summarizePerformance words the performance phase by its slowest tool,
// or by the round trip when no tool was timed.
func summarizePerformance(s *Session) string {
	if s.Perf == nil || len(s.Perf.Tools) == 0 {
		if s.Perf != nil && s.Perf.Ping != nil {
			return fmt.Sprintf("Round trip %s", ms(s.Perf.Ping.P50))
		}
		return "Not measured"
	}
	var worst Millis
	worstName := ""
	for _, t := range s.Perf.Tools {
		if t.P95 > worst {
			worst, worstName = t.P95, t.Name
		}
	}
	if worst.Duration() > 2*time.Second {
		return fmt.Sprintf("Slow: %s takes up to %.1fs", worstName, worst.Duration().Seconds())
	}
	return fmt.Sprintf("Fast, slowest tool answers in %s", ms(worst))
}

// summarizeResilience words the resilience phase: session recovery, or on
// a stateless server, independence from the connection.
func summarizeResilience(s *Session, pr PhaseResult, t phaseTally) string {
	if pr.Status == Skip {
		return "Stateless server, nothing to recover"
	}
	if s.Stateless() {
		// There is no session to recover; what was checked is whether
		// the server really is independent of the connection.
		switch {
		case t.fails > 0:
			return "Requests depend on the connection they arrive on"
		case t.warns > 0:
			return "Stateless, with a caveat"
		}
		return "Genuinely stateless: any request can land on any instance"
	}
	if t.fails > 0 {
		return "Does not recover cleanly"
	}
	if t.warns > 0 {
		return "Recovers, with a caveat"
	}
	return "Recovers from a lost session"
}

func plural(n int, singular string, pluralForm ...string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	if len(pluralForm) > 0 {
		return fmt.Sprintf("%d %s", n, pluralForm[0])
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

func firstSentence(s string) string {
	if i := strings.IndexAny(s, ".;:("); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func firstWords(s string, n int) string {
	w := strings.Fields(s)
	if len(w) > n {
		w = w[:n]
	}
	return strings.Join(w, " ")
}

func hostOf(issuer string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	return s
}
