// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// upstreamTries bounds how many tools are called with their dependencies
// down. One that reaches for the network is the evidence; three is enough
// to find one without re-running the execution phase. The first hang ends
// the search, so the check costs at most one call timeout of waiting.
const upstreamTries = 3

// upstreamCandidates picks the tools to call again: those that succeeded,
// slowest first, at most upstreamTries of them.
func upstreamCandidates(results []ToolResult) []ToolResult {
	var candidates []ToolResult
	for _, r := range results {
		if r.Executed && r.OK {
			candidates = append(candidates, r)
		}
	}
	// Slowest first: a call that waited on the network is the likeliest to
	// have one, and the order is stable for two runs to compare.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Duration != candidates[j].Duration {
			return candidates[i].Duration > candidates[j].Duration
		}
		return candidates[i].Name < candidates[j].Name
	})
	if len(candidates) > upstreamTries {
		candidates = candidates[:upstreamTries]
	}
	return candidates
}

// upstreamOutcome sorts the repeated calls by what they did with their
// upstream down.
type upstreamOutcome struct {
	legible, hung, answered, untouched []string
}

// call repeats one tool with every upstream failing and files the result.
// It reports false when the search should stop.
func (o *upstreamOutcome) call(ctx context.Context, s *Session, r ToolResult) bool {
	before := s.Proxy.Failed()
	cctx, cancel := context.WithTimeout(ctx, s.Opts.CallTimeout)
	t0 := time.Now()
	res, err := s.Client.CallTool(cctx, r.Name, r.Arguments)
	d := time.Since(t0)
	timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
	cancel()
	if s.Proxy.Failed() == before {
		o.untouched = append(o.untouched, r.Name)
		return true
	}
	if timedOut {
		// One is the finding; waiting out the timeout again for the
		// next tool would add time and nothing else.
		o.hung = append(o.hung, fmt.Sprintf("%s (no answer in %s)", r.Name, s.Opts.CallTimeout))
		return false
	}
	switch {
	case err != nil:
		o.legible = append(o.legible, fmt.Sprintf("%s: error in %s: %s", r.Name, ms(d), truncate(err.Error(), 120)))
	case res.IsError:
		o.legible = append(o.legible, fmt.Sprintf("%s: isError in %s: %s", r.Name, ms(d), truncate(res.Text(), 120)))
	default:
		o.answered = append(o.answered, fmt.Sprintf("%s in %s", r.Name, ms(d)))
	}
	return true
}

// checkUpstreamDown asks what an agent sees when the thing a tool depends
// on is down: an error it can act on, or a call that never returns.
//
// The server is not touched. Its proxy — the one --watch-egress already
// points it at — answers every connection as an unreachable upstream, and
// tools that succeeded earlier in the run are called again with the same
// arguments. A call only counts if the server tried to connect during it;
// a tool that answered from memory tells nothing about its dependencies.
//
// Nothing here runs unless the operator asked with --fault-upstream, so a
// default run's requests are unchanged.
func checkUpstreamDown(ctx context.Context, s *Session) []Finding {
	if !s.Opts.FaultUpstream {
		return nil
	}
	c := s.check("resilience.upstream_down", "Tool calls with every upstream unreachable")
	if reason := upstreamSkipReason(s); reason != "" {
		return []Finding{c.skip(reason)}
	}
	candidates := upstreamCandidates(s.ToolResults)
	if len(candidates) == 0 {
		return []Finding{c.skip("no tool completed successfully in the execution phase, so there is no call to repeat")}
	}

	s.Proxy.SetFailing(true)
	defer s.Proxy.SetFailing(false)

	var o upstreamOutcome
	for _, r := range candidates {
		if !o.call(ctx, s, r) {
			break
		}
	}
	legible, hung, answered, untouched := o.legible, o.hung, o.answered, o.untouched
	if exited, werr := s.Pipe.Exited(); exited {
		detail := "the server exited when its upstreams were unreachable"
		if werr != nil {
			detail += ": " + werr.Error()
		}
		return []Finding{c.fail(Major, detail,
			"a dependency being down is ordinary; catch the connection error and return it as a tool error so the agent can say what failed and the next call still has a server")}
	}
	switch {
	case len(hung) > 0:
		return []Finding{c.fail(Major, "with its upstream unreachable, "+strings.Join(hung, ", ")+" did not come back",
			"put a timeout on every outbound call shorter than the host's, and return the failure as a tool error: an agent waiting on a call that will never finish cannot tell a slow answer from a dead one")}
	case len(legible) > 0 || len(answered) > 0:
		parts := append([]string{}, legible...)
		if len(answered) > 0 {
			parts = append(parts, "answered anyway (a cache or a fallback): "+strings.Join(answered, ", "))
		}
		return []Finding{c.pass(strings.Join(parts, "; "))}
	}
	return []Finding{c.info(fmt.Sprintf("none of the %d tools called (%s) connected to anything while upstreams were failing, so none was tested",
		len(untouched), strings.Join(untouched, ", ")))}
}

// upstreamSkipReason is why the upstream-down check cannot run, or "" when
// it can: it needs an egress proxy the server actually dialled through, and
// a server that is still running.
func upstreamSkipReason(s *Session) string {
	switch {
	case s.Proxy == nil && s.egressErr != "":
		return "no egress proxy, so there is nothing to fail: " + s.egressErr
	case s.Proxy == nil:
		return "no egress proxy, so there is nothing to fail"
	case len(s.Proxy.Dials()) == 0:
		return "the server connected to nothing through the proxy during the run, so it has no upstream to lose"
	}
	if exited, _ := s.Pipe.Exited(); exited {
		return "the server had already exited"
	}
	return ""
}
