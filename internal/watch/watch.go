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
	// Kind is "pulse", "drift", "error" or "settled".
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
}

// Run watches until the context is cancelled, or once when Once is set.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Sink == nil {
		return nil, errors.New("watch: a sink is required")
	}
	if opts.Approved == nil {
		return nil, errors.New("watch: nothing to compare against; approve a baseline first")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Interval < MinInterval {
		return nil, fmt.Errorf("watch: an interval under %s would make this the abusive client passmcp warns about", MinInterval)
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	res := &Result{}
	target := targetName(opts.Spec)

	for {
		snap, changes, err := pulse(ctx, opts)
		res.Pulses++

		switch {
		case err != nil:
			// A server that cannot be reached is not a server that
			// changed, and reporting it as drift would make every network
			// blip an incident. It is still worth saying out loud.
			opts.Sink(Event{
				At: opts.Now(), Kind: "error", Target: target, Err: err.Error(),
				Detail: "could not reach the server: " + err.Error(),
			})
		case len(changes) == 0:
			res.Latest = snap
			opts.Sink(Event{
				At: opts.Now(), Kind: "pulse", Target: target, Digest: snap.Digest,
				Detail: fmt.Sprintf("unchanged, %d tool(s)", len(snap.Tools)),
			})
		default:
			res.Latest = snap
			res.Drifted = true
			worst := baseline.Worst(changes)
			if worst > res.Worst {
				res.Worst = worst
			}
			opts.Sink(Event{
				At: opts.Now(), Kind: "drift", Target: target, Digest: snap.Digest,
				Changes: changes, Severity: worst.String(),
				Detail: fmt.Sprintf("%d change(s) since the catalogue was approved, worst %s",
					len(changes), worst),
			})
		}

		if opts.Once {
			return res, nil
		}
		select {
		case <-ctx.Done():
			opts.Sink(Event{
				At: opts.Now(), Kind: "settled", Target: target,
				Detail: fmt.Sprintf("stopped after %d pulse(s)", res.Pulses),
			})
			return res, nil
		case <-time.After(opts.Interval):
		}
	}
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
