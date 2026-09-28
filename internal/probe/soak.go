// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/witness"
)

// A soak asks the one question fifty requests cannot: does the server's
// memory settle, or does every call leave something behind? A host keeps
// one process for a whole session, and a server that grows by a few
// kilobytes a call is fine in a demo and dead by the afternoon.
//
// The measurement is the slope, not the peak. Every runtime grows its heap
// while it warms up and most hold a sawtooth afterwards, so the first
// samples are dropped and a line is fitted through the rest; a line that
// explains the variation and adds up to something is the finding. It is
// read from /proc after every call, which is why this is Linux-only and
// stdio-only: passmcp has to own the process to know its memory.
//
// Nothing here runs unless the operator asked with --soak, and the calls
// it makes go through the same throttle as the rest of the run.

// SoakMinCalls is the fewest calls a soak may be asked for. Below it a
// slope is noise with a sign.
const SoakMinCalls = 100

const (
	// soakWarmup is the share of samples dropped from the front before
	// the line is fitted. A runtime that grows for its first few dozen
	// calls and then holds is behaving well, and a line through the
	// growth would say otherwise.
	soakWarmup = 0.1
	// soakMinR2 is how much of the variation the line has to explain
	// before its slope is trusted. A garbage collector's sawtooth has a
	// slope; it does not have a fit.
	soakMinR2 = 0.6
	// soakMinGrowth and soakMinShare set the floor under what counts:
	// at least sixteen mebibytes, and at least this share of where it
	// started, so a small server and a large one are judged by the same
	// rule. The floor is high on purpose. A runtime growing its heap
	// towards its first collection rises in a straight line for as long
	// as the window is shorter than one collection cycle, and a Go
	// process's first cycle is several mebibytes of garbage; a rise that
	// small cannot be told from that ramp by its shape, so it is not
	// called a leak. The numbers are still in the finding.
	soakMinGrowth = 16 << 20
	soakMinShare  = 0.25
	// soakTailShare is how much of the whole line's slope the last quarter
	// of the window has to keep. A leak is a line; a heap that is
	// settling is a curve that flattens, and its last quarter says so.
	soakTailShare = 0.5
)

// trend is a least-squares line through resident memory against call
// number, fitted over the samples after warm-up.
type trend struct {
	// Start and End are the first and last samples of the fitted window;
	// Peak is the highest sample anywhere.
	Start, End, Peak int64
	// Slope is in bytes per call. Tail is the same over the last quarter
	// of the window, which says whether the rise was still going on at
	// the end or had flattened.
	Slope, Tail float64
	// R2 is how much of the variation the line explains, 0 to 1.
	R2 float64
	// Window is how many samples the line was fitted through; Calls is
	// how many there were in all.
	Window, Calls int
}

// fitTrend fits the line. Fewer than two samples after warm-up means the
// whole series is used; fewer than two in all means no line.
func fitTrend(samples []int64) trend {
	t := trend{Calls: len(samples)}
	if len(samples) == 0 {
		return t
	}
	t.Peak = samples[0]
	for _, v := range samples {
		t.Peak = max(t.Peak, v)
	}
	window := samples[int(float64(len(samples))*soakWarmup):]
	if len(window) < 2 {
		window = samples
	}
	t.Window = len(window)
	t.Start, t.End = window[0], window[len(window)-1]
	if len(window) < 2 {
		return t
	}
	t.Slope, t.R2 = fitLine(window)
	if tail := window[len(window)*3/4:]; len(tail) >= 2 {
		t.Tail, _ = fitLine(tail)
	}
	return t
}

// fitLine is the least-squares slope and r² of samples against their
// index. Two or more samples.
func fitLine(samples []int64) (slope, r2 float64) {
	n := float64(len(samples))
	xBar := (n - 1) / 2
	var yBar float64
	for _, v := range samples {
		yBar += float64(v)
	}
	yBar /= n
	var sxy, sxx, syy float64
	for i, v := range samples {
		dx, dy := float64(i)-xBar, float64(v)-yBar
		sxy += dx * dy
		sxx += dx * dx
		syy += dy * dy
	}
	slope = sxy / sxx
	if syy > 0 {
		r2 = sxy * sxy / (sxx * syy)
	}
	return slope, r2
}

// Growth is what the line says was added over the window.
func (t trend) Growth() float64 { return t.Slope * float64(t.Window-1) }

// Rising reports whether the line is a leak rather than noise or a heap
// settling: it has to fit, it has to add up to something, and it has to
// still be rising at the end.
func (t trend) Rising() bool {
	if t.Window < 2 || t.Slope <= 0 || t.R2 < soakMinR2 {
		return false
	}
	if t.Growth() < math.Max(soakMinGrowth, soakMinShare*float64(t.Start)) {
		return false
	}
	return t.Tail >= soakTailShare*t.Slope
}

// soakCandidate picks the tool to repeat: the fastest that succeeded, so a
// thousand calls cost the least, and by name among equals so two runs
// pick the same one.
func soakCandidate(results []ToolResult) (ToolResult, bool) {
	var ok []ToolResult
	for _, r := range results {
		if r.Executed && r.OK {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return ToolResult{}, false
	}
	sort.SliceStable(ok, func(i, j int) bool {
		if ok[i].Duration != ok[j].Duration {
			return ok[i].Duration < ok[j].Duration
		}
		return ok[i].Name < ok[j].Name
	})
	return ok[0], true
}

// checkSoak repeats one call and reads the server's resident memory after
// each, then judges the line through the samples.
func checkSoak(ctx context.Context, s *Session) []Finding {
	if s.Opts.Soak <= 0 {
		return nil
	}
	c := s.check("resilience.soak_memory", "Resident memory over a long run of calls")
	if s.Pipe == nil {
		return []Finding{c.skip("resident memory is read from the process passmcp started, and this run started none")}
	}
	if exited, _ := s.Pipe.Exited(); exited {
		return []Finding{c.skip("the server had already exited")}
	}
	tool, ok := soakCandidate(s.ToolResults)
	if !ok {
		return []Finding{c.skip("no tool completed successfully in the execution phase, so there is no call to repeat")}
	}
	pid := s.Pipe.PID()
	first, err := witness.RSS(pid)
	switch {
	case errors.Is(err, witness.ErrUnsupported):
		return []Finding{c.skip("only Linux publishes a process's resident memory under /proc")}
	case err != nil:
		return []Finding{c.skip("resident memory could not be read: " + err.Error())}
	}
	const advice = "find what each call allocates and never frees: a cache with no bound, a listener or a timer registered per request, a connection opened and not closed. A host keeps one process for the whole session, so memory that only grows is a server that only runs for so long"

	r := soakRun{s: s, c: c, tool: tool, pid: pid, first: first, samples: []int64{first}, advice: advice}
	if stop := r.repeat(ctx); stop != nil {
		return []Finding{*stop}
	}
	samples, toolErrs, readErr := r.samples, r.toolErrs, r.readErr

	t := fitTrend(samples)
	detail := fmt.Sprintf("%s → %s over %s to %s (peak %s); %s per call after a %d-call warm-up, r² %.2f, %s per call over the last quarter",
		mib(t.Start), mib(t.End), plural(len(samples)-1, "call"), tool.Name, mib(t.Peak), kibPerCall(t.Slope), len(samples)-t.Window, t.R2, kibPerCall(t.Tail))
	if toolErrs > 0 {
		detail += fmt.Sprintf("; %s answered isError", plural(toolErrs, "call"))
	}
	detail += readErr
	if t.Rising() {
		return []Finding{c.fail(Major, "resident memory rose steadily: "+detail, advice)}
	}
	return []Finding{c.pass(detail)}
}

// soakRun is the state of one soak: the call being repeated, the memory
// samples so far, and what the calls answered.
type soakRun struct {
	s        *Session
	c        *check
	tool     ToolResult
	pid      int
	first    int64
	samples  []int64
	advice   string
	toolErrs int
	readErr  string
}

// repeat makes the soak's calls, sampling resident memory after each. It
// returns the finding that ends the check early, or nil when the samples
// are ready to judge.
func (r *soakRun) repeat(ctx context.Context) *Finding {
	s := r.s
	limiter := diagnostics.NewLimiter(s.Opts.RPS, 1)
	for i := 1; i <= s.Opts.Soak; i++ {
		if err := limiter.Wait(ctx); err != nil {
			f := r.c.skip(fmt.Sprintf("stopped after %d of %d calls: %s", i-1, s.Opts.Soak, err))
			return &f
		}
		cctx, cancel := context.WithTimeout(ctx, s.Opts.CallTimeout)
		res, err := s.Client.CallTool(cctx, r.tool.Name, r.tool.Arguments)
		timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
		cancel()
		if err != nil {
			f := r.callFailed(i, err, timedOut)
			return &f
		}
		if res.IsError {
			r.toolErrs++
		}
		rss, err := witness.RSS(r.pid)
		if err != nil {
			if exited, _ := s.Pipe.Exited(); exited {
				f := r.c.fail(Major, fmt.Sprintf("the server exited after call %d of %d to %s (resident memory %s at the start, %s before the call)",
					i, s.Opts.Soak, r.tool.Name, mib(r.first), mib(r.samples[len(r.samples)-1])), r.advice)
				return &f
			}
			r.readErr = fmt.Sprintf("; sampling stopped after call %d: %s", i, err)
			break
		}
		r.samples = append(r.samples, rss)
	}
	return nil
}

// callFailed is the verdict on call i returning an error: the server exited
// during it, it timed out, or it failed.
func (r *soakRun) callFailed(i int, err error, timedOut bool) Finding {
	s := r.s
	so := fmt.Sprintf("(resident memory %s at the start, %s before the call)", mib(r.first), mib(r.samples[len(r.samples)-1]))
	if exited, werr := s.Pipe.Exited(); exited {
		detail := fmt.Sprintf("the server exited during call %d of %d to %s %s", i, s.Opts.Soak, r.tool.Name, so)
		if werr != nil {
			detail += ": " + werr.Error()
		}
		return r.c.fail(Major, detail, r.advice)
	}
	what := "failed: " + truncate(err.Error(), 120)
	if timedOut {
		what = fmt.Sprintf("did not come back within %s", s.Opts.CallTimeout)
	}
	return r.c.fail(Major, fmt.Sprintf("call %d of %d to %s %s %s", i, s.Opts.Soak, r.tool.Name, what, so),
		"a call that succeeded once and fails after a few hundred repetitions is a resource the server runs out of: file descriptors, connections, threads or memory. Find which count grows with the calls")
}

// mib renders bytes as mebibytes to one decimal.
func mib(b int64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }

// kibPerCall renders a slope, signed, in kibibytes.
func kibPerCall(bytes float64) string { return fmt.Sprintf("%+.1f KiB", bytes/(1<<10)) }
