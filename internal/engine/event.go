// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// EventKind distinguishes what happened.
type EventKind string

// The events a run emits, in the order they can occur.
const (
	// EventPhaseStart fires as a phase begins.
	EventPhaseStart EventKind = "phase_start"
	// EventFinding fires as each finding lands.
	EventFinding EventKind = "finding"
	// EventPhaseDone fires with the phase's result, including skips.
	EventPhaseDone EventKind = "phase_done"
	// EventRequest fires for each HTTP exchange, when the surface asked
	// for telemetry.
	EventRequest EventKind = "request"
)

// Event is one thing that happened during a run.
//
// This is the contract the three surfaces share: the TUI draws it, the
// CLI serialises it as NDJSON, and the web UI forwards it as SSE. One
// producer, three consumers, and no per-surface logic inside the engine.
type Event struct {
	Kind EventKind `json:"type"`
	// Phase names the phase the event belongs to.
	Phase string `json:"phase,omitempty"`
	// Finding is set for EventFinding.
	Finding *probe.Finding `json:"finding,omitempty"`
	// Result is set for EventPhaseDone.
	Result *probe.PhaseResult `json:"result,omitempty"`
	// Request is set for EventRequest.
	Request *telemetry.Event `json:"event,omitempty"`
}

// Sink receives events as a run proceeds. A nil Sink is valid and means
// the caller wants only the final report.
//
// It is an interface rather than a channel so a surface that draws
// synchronously (the TUI) does not have to run a pump, and one that wants
// a channel can wrap it in three lines. Implementations must be safe for
// concurrent use and must not block for long: the run holds no buffer and
// a slow sink slows the diagnostic it is reporting on.
type Sink interface {
	Emit(Event)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(Event)

// Emit implements Sink.
func (f SinkFunc) Emit(e Event) { f(e) }
