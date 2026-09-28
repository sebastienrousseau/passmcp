// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"time"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/otlp"
)

// ExportTraces sends the finished run to the spec's OTLP collector.
//
// It lives on the engine rather than in the CLI for the same reason Render
// does: a capability reachable from only one surface is a capability the
// other two do not have. `passmcp serve` exports the same spans from the same
// spec without knowing how they are built.
//
// A nil error with no endpoint configured is the normal case.
func (r *Result) ExportTraces(ctx context.Context, spec RunSpec, version string) error {
	if spec.Output.OTLPEndpoint == "" || r.Report == nil {
		return nil
	}

	headers := map[string]string{}
	for _, h := range spec.Output.OTLPHeaders {
		k, v, err := creds.ParseHeader(h)
		if err != nil {
			return err
		}
		headers[k] = v
	}

	events := r.Report.Events
	if r.Recorder != nil {
		// The report carries events only when --events was asked for; the
		// recorder always has them, and a trace with no request spans is
		// most of the value missing.
		events = r.Recorder.Events()
	}

	run := otlp.Run{
		TraceID:    r.Report.TraceID,
		Endpoint:   r.Report.Target.Endpoint,
		Host:       r.Report.Target.Host,
		Started:    r.Report.Started,
		Duration:   time.Duration(r.Report.Duration),
		Phases:     r.Report.Phases,
		Events:     events,
		Failed:     r.Report.Counts.Fail,
		Warned:     r.Report.Counts.Warn,
		ScoreTotal: r.Report.Score.Total,
	}
	return otlp.Exporter{
		Endpoint:       spec.Output.OTLPEndpoint,
		Headers:        headers,
		ServiceVersion: version,
	}.Export(ctx, run)
}
