// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/policy"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
)

// Result is everything a run produced.
type Result struct {
	// Report is the rendered-ready document. It is non-nil whenever the
	// run reached the point of having something to say, including a run
	// that stopped early.
	Report *report.Report
	// Session is the raw probe state, for a surface that wants more than
	// the report carries.
	Session *probe.Session
	// Recorder holds the telemetry, for writing a report directory or
	// streaming a HAR.
	Recorder *telemetry.Recorder
	// Err is the reason a run did not finish, or nil. A Result can carry
	// both a Report and an Err: the report describes how far it got.
	Err error
	// Gate is the acceptance policy's answer, when the spec carried one.
	//
	// Evaluated here rather than in a surface, for the reason the package
	// comment gives: a policy decision that lived in the CLI would be a
	// decision the web UI could not make, and the two would eventually
	// disagree about whether the same server was acceptable.
	Gate *policy.Result
}

// Failed reports whether the run should be treated as a failure, which is
// what every surface turns into its own kind of non-zero exit.
//
// A policy replaces the default rule rather than adding to it. That is the
// whole point of an exemption: a team that has decided, in writing and with
// an expiry, that one failing check is acceptable on this server has to get a
// pass — otherwise the exemption changes nothing and the gate gets turned off
// instead. The policy's own output names every failure it excused, so the
// pass is never silent.
func (r *Result) Failed() bool {
	if r.Gate != nil {
		return !r.Gate.OK
	}
	return r.Report != nil && r.Report.Counts.Fail > 0
}

// Run executes one diagnostic against one server.
//
// This is the only entry point. The CLI, the TUI and the web UI each build
// a RunSpec and call it; none of them contains a check, a policy decision,
// or a default the others lack. Events arrive on sink as the run proceeds;
// a nil sink is valid and means the caller wants only the result.
//
// Run holds no package-level state, so a process may have any number of
// runs in flight at once — which is the property the web UI needs and the
// reason this package exists.
func Run(ctx context.Context, spec RunSpec, sink Sink) *Result {
	spec = spec.WithDefaults()
	if err := spec.Validate(); err != nil {
		return &Result{Err: err}
	}
	cr, err := spec.Credentials()
	if err != nil {
		return &Result{Err: err}
	}

	rec := telemetry.New()
	rec.CaptureBodies = spec.Output.CaptureBodies
	if sink != nil {
		rec.Sink = func(e telemetry.Event) {
			ev := e
			sink.Emit(Event{Kind: EventRequest, Request: &ev})
		}
	}

	res := &Result{Recorder: rec}
	opts := spec.probeOptions(cr, rec, sink)

	sess, runErr := probe.Run(ctx, opts)
	res.Session, res.Err = sess, runErr
	if sess != nil {
		res.Report = report.Build(sess, spec.Version, spec.Output.WithEvents || spec.Output.ReportDir != "")
		res.Report.Plan = spec.Plan(rec.Redactor)
	}
	if spec.Gate != nil && res.Report != nil {
		g := spec.Gate.Evaluate(policy.FromReport(res.Report), time.Now())
		res.Gate = &g
	}
	return res
}

// probeOptions translates the spec into what the probe layer takes.
func (s RunSpec) probeOptions(cr *creds.Credentials, rec *telemetry.Recorder, sink Sink) probe.Options {
	opts := probe.Options{
		Endpoint:  s.Target.Endpoint,
		UserAgent: s.Target.UserAgent,
		Creds:     cr,
		Store:     &creds.Store{},
		Recorder:  rec,
		Version:   s.Version,
		// The outer client timeout has to outlast the per-call one, or a
		// slow-but-answering tool is reported as a transport failure.
		HTTPClient: &http.Client{Timeout: s.Pacing.CallTimeout + 30*time.Second},

		Policy:                s.diagnosticsPolicy(),
		URLPolicy:             s.urlPolicy(),
		AllowResourceMismatch: s.Policy.AllowResourceMismatch,
		SkipEraCheck:          s.Policy.SkipEraCheck,

		Samples:       s.Pacing.Samples,
		Concurrency:   s.Pacing.Concurrency,
		RPS:           s.Pacing.RPS,
		CallTimeout:   s.Pacing.CallTimeout,
		Seed:          s.Pacing.Seed,
		FillOptional:  s.Pacing.FillOptional,
		AllowLoad:     s.Pacing.AllowLoad,
		MaxResources:  s.Pacing.MaxResources,
		MaxPrompts:    s.Pacing.MaxPrompts,
		Soak:          s.Pacing.Soak,
		ToolArgs:      s.Policy.ToolArgs,
		Baseline:      s.Baseline,
		ClientConfig:  s.ClientConfig,
		WatchEgress:   s.Egress.Watch || s.Egress.FaultUpstream,
		ExpectEgress:  s.Egress.Expect,
		PlantCanaries: s.Egress.Canaries,
		FaultUpstream: s.Egress.FaultUpstream,

		Only: s.Phases.Only,
		Skip: s.Phases.Skip,
	}
	if s.Target.Stdio() {
		opts.Endpoint = ""
		opts.Stdio = &passmcp.StdioConfig{
			Command: s.Target.Command,
			Args:    s.Target.Args,
			Dir:     s.Target.Dir,
			Env:     s.Target.Env,
			PassEnv: s.Target.PassEnv,
		}
		// Nothing over a pipe goes through an http.Client, and leaving one
		// here would suggest otherwise to the next reader.
		opts.HTTPClient = nil
	}
	if sink == nil {
		return opts
	}
	opts.Progress = func(phase string, f *probe.Finding) {
		if f == nil {
			sink.Emit(Event{Kind: EventPhaseStart, Phase: phase})
			return
		}
		finding := *f
		sink.Emit(Event{Kind: EventFinding, Phase: phase, Finding: &finding})
	}
	opts.PhaseDone = func(pr probe.PhaseResult) {
		result := pr
		sink.Emit(Event{Kind: EventPhaseDone, Phase: pr.Name, Result: &result})
	}
	return opts
}

// SelectTools narrows a spec to the named tools, recording the widening a
// deliberate choice implies.
//
// An interactive selector is a surface concern — a terminal draws one way
// and a browser another — but what it produces is not: choosing a tool is
// an explicit opt-in, so the policy widens to cover what was chosen. Doing
// that here means every surface widens it identically, and the resulting
// spec reproduces the run without asking again.
func (s *RunSpec) SelectTools(names []string, kinds map[string]string) {
	if len(names) == 0 {
		return
	}
	s.Policy.Only = append([]string(nil), names...)
	for _, n := range names {
		switch kinds[n] {
		case "mutating":
			s.Policy.AllowMutations = true
		case "destructive":
			s.Policy.AllowDestructive = true
		}
	}
}

// ToolPolicy exposes the tool-invocation policy, for a surface that needs
// to decide what to show in a selector before the run starts.
func (s RunSpec) ToolPolicy() diagnostics.Policy { return s.diagnosticsPolicy() }

// PhaseNames lists the phases a spec will run, in order, after Only and
// Skip are applied. Surfaces use it to draw a checklist before the run
// starts.
func (s RunSpec) PhaseNames() []string {
	var out []string
	for _, name := range probe.PhaseNames() {
		if len(s.Phases.Only) > 0 && !contains(s.Phases.Only, name) {
			continue
		}
		if contains(s.Phases.Skip, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// String renders the spec's target for a log line, without secrets.
func (s RunSpec) String() string {
	return fmt.Sprintf("passmcp run %s (%s)", s.Target.Describe(), s.Creds.Mode)
}
