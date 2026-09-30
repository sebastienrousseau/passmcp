// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package watch tells you a server is still the one you reviewed.
//
// A check tells you a server was sound when you ran it. That is a
// statement about a moment, and the threat it cannot see by construction
// is the one that waits: the server that passes review and edits its tool
// descriptions the following week is the server that gets through.
// --baseline closes that gap for anyone who remembers to run it again.
// This is the part that does the remembering.
//
// # A watcher has to be polite
//
// passmcp tells every operator to throttle, and a watcher that re-ran nine
// phases on a loop would be the abusive client it warns about. So a pulse
// is deliberately small: connect, list the catalogue, hash it, compare.
// Two requests and a string comparison, which is what the content address
// in a baseline snapshot was for. A full diagnostic is what happens when
// the hash moves, not what happens every few minutes.
//
// Between pulses there is a timer and nothing else — no polling loop, no
// spin. A process that is going to run for months earns that.
package watch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/engine"
)

// DefaultInterval is how long a watcher waits between pulses.
//
// Minutes rather than seconds. A rug pull is a thing somebody deploys, not
// a thing that happens between two heartbeats, and the cost of noticing it
// four minutes later is nothing next to the cost of being the client that
// hammers a server all day.
const DefaultInterval = 5 * time.Minute

// MinInterval is the shortest pulse the watcher will accept.
const MinInterval = 30 * time.Second

// Event is one thing the watcher saw.
type Event struct {
	// At is when, in UTC.
	At time.Time `json:"at"`
	// Kind is "pulse", "drift", "error", "settled" or "summary".
	Kind string `json:"kind"`
	// Target is the server being watched.
	Target string `json:"target"`
	// Digest is the catalogue's content address at this pulse.
	Digest string `json:"digest,omitempty"`
	// Changes is what differs from the approved snapshot, worst first.
	Changes []baseline.Change `json:"changes,omitempty"`
	// Severity is the worst change, as a word.
	Severity string `json:"severity,omitempty"`
	// Err is why a pulse failed, when one did.
	Err string `json:"error,omitempty"`
	// LatencyMS is how long the pulse took, connect to listing, in
	// milliseconds. Set on every pulse, answered or not.
	LatencyMS float64 `json:"latency_ms,omitempty"`
	// Status is the class of the pulse's outcome (ok, protocol_error,
	// transport_error, auth_error or timeout). Set on every pulse.
	Status string `json:"status,omitempty"`
	// ErrorKind narrows a failed pulse's Status, such as
	// connection_refused or jsonrpc_-32601.
	ErrorKind string `json:"error_kind,omitempty"`
	// Summary is the availability of the run so far, on a "summary"
	// event.
	Summary *Summary `json:"summary,omitempty"`
	// Detail is a sentence for a person.
	Detail string `json:"detail"`
}

// Sink receives events as they happen.
type Sink func(Event)

// Options configure a watcher.
type Options struct {
	// Spec says what to connect to and how.
	Spec engine.RunSpec
	// Approved is the catalogue somebody signed off.
	Approved *baseline.Snapshot
	// Interval is the pulse period; zero means DefaultInterval.
	Interval time.Duration
	// Once takes a single pulse and returns, which is the shape a CI job
	// wants: one answer, one exit code.
	Once bool
	// Version is the passmcp build identifier, for the client it presents.
	Version string
	// Sink receives every event. Required.
	Sink Sink
	// Now is the clock, for tests.
	Now func() time.Time
}

// Result is what a watch run concluded.
type Result struct {
	// Pulses is how many were taken.
	Pulses int
	// Drifted is whether the catalogue ever differed from the approved
	// one. It is the exit code: a watcher that saw a change and returned
	// zero would be a gate that never fails.
	Drifted bool
	// Worst is the highest severity seen.
	Worst baseline.Severity
	// Latest is the most recent snapshot, which is what --approve
	// promotes.
	Latest *baseline.Snapshot
	// Target is the server that was watched, as reports name it.
	Target string
	// Summary is the availability and latency of the pulses taken.
	Summary Summary
}

// SummaryEvent is the run's summary as the event that closes a stream.
func (r *Result) SummaryEvent(at time.Time) Event {
	sum := r.Summary
	return Event{At: at, Kind: "summary", Target: r.Target, Summary: &sum, Detail: sum.Sentence()}
}

// Run watches until the context is cancelled, or once when Once is set.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if err := opts.normalise(); err != nil {
		return nil, err
	}
	w := &watcher{opts: opts, res: &Result{Target: targetName(opts.Spec)}}
	for w.step(ctx) {
		if opts.Once || !w.wait(ctx) {
			break
		}
	}
	w.res.Summary = w.stats.Summary()
	return w.res, nil
}

// normalise fills defaults and refuses options a watcher cannot run with.
func (o *Options) normalise() error {
	if o.Sink == nil {
		return errors.New("watch: a sink is required")
	}
	if o.Approved == nil {
		return errors.New("watch: nothing to compare against; approve a baseline first")
	}
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Interval < MinInterval {
		return fmt.Errorf("watch: an interval under %s would make this the abusive client passmcp warns about", MinInterval)
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	return nil
}

// watcher is one run's state between pulses.
type watcher struct {
	opts  Options
	res   *Result
	stats Stats
}

// step takes one pulse, records it and reports it. It returns false when
// the pulse was cut short by the context: that is the operator leaving,
// not the server failing, so it is neither counted nor reported as an
// error.
//
// The pulse is timed as it is taken. Measuring availability adds no
// request, so it cannot turn the watcher into the load generator
// MinInterval exists to prevent.
func (w *watcher) step(ctx context.Context) bool {
	t0 := time.Now()
	snap, changes, err := pulse(ctx, w.opts)
	latency := time.Since(t0)
	if err != nil && ctx.Err() != nil {
		w.settle()
		return false
	}
	st, kind := Classify(err)
	w.stats.Observe(st, kind, latency)
	w.res.Pulses++
	ev := w.event(snap, changes, err)
	ev.LatencyMS = float64(latency) / float64(time.Millisecond)
	ev.Status, ev.ErrorKind = string(st), kind
	w.opts.Sink(ev)
	return true
}

// event describes one completed pulse, and folds it into the result.
func (w *watcher) event(snap *baseline.Snapshot, changes []baseline.Change, err error) Event {
	ev := Event{At: w.opts.Now(), Target: w.res.Target}
	switch {
	case err != nil:
		// A server that cannot be reached is not a server that
		// changed, and reporting it as drift would make every network
		// blip an incident. It is still worth saying out loud.
		ev.Kind, ev.Err = "error", err.Error()
		ev.Detail = "could not reach the server: " + err.Error()
	case len(changes) == 0:
		w.res.Latest = snap
		ev.Kind, ev.Digest = "pulse", snap.Digest
		ev.Detail = fmt.Sprintf("unchanged, %d tool(s)", len(snap.Tools))
	default:
		w.res.Latest = snap
		w.res.Drifted = true
		worst := baseline.Worst(changes)
		w.res.Worst = max(w.res.Worst, worst)
		ev.Kind, ev.Digest, ev.Changes, ev.Severity = "drift", snap.Digest, changes, worst.String()
		ev.Detail = fmt.Sprintf("%d change(s) since the catalogue was approved, worst %s", len(changes), worst)
	}
	return ev
}

// wait sleeps until the next pulse. It returns false, having said how far
// the watcher got, when the context ends first.
func (w *watcher) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		w.settle()
		return false
	case <-time.After(w.opts.Interval):
		return true
	}
}

// settle reports that the watcher stopped.
func (w *watcher) settle() {
	w.opts.Sink(Event{
		At: w.opts.Now(), Kind: "settled", Target: w.res.Target,
		Detail: fmt.Sprintf("stopped after %d pulse(s)", w.res.Pulses),
	})
}

// pulse takes one reading.
func pulse(ctx context.Context, opts Options) (*baseline.Snapshot, []baseline.Change, error) {
	tools, err := engine.ListCatalogue(ctx, opts.Spec, opts.Version)
	if err != nil {
		return nil, nil, err
	}
	snap := baseline.Take(targetName(opts.Spec), tools)

	// The cheap path, and the reason a pulse is affordable on a schedule:
	// one string comparison answers the common case without walking
	// anything.
	if snap.Digest == opts.Approved.Digest {
		return &snap, nil, nil
	}
	return &snap, baseline.Diff(*opts.Approved, snap), nil
}

// targetName is how the server is named in a report.
func targetName(spec engine.RunSpec) string {
	if spec.Target.Stdio() {
		return spec.Target.Command
	}
	return spec.Target.Endpoint
}
