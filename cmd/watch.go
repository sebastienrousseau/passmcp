// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/termsafe"
	"satellion.com/passmcp/internal/watch"
)

var (
	watchInterval time.Duration
	watchOnce     bool
)

var watchCmd = &cobra.Command{
	Use:   "watch <endpoint>",
	Short: "Report when a server stops being the one you approved.",
	Long: `Watch a server's catalogue and report what changed.

A check tells you a server was sound when you ran it. That is a statement
about a moment, and the threat it cannot see by construction is the one
that waits: the server that passes review and edits its tool descriptions
the following week is the server that gets through.

  passmcp check URL --baseline .passmcp/baseline.json --approve
  passmcp watch URL --baseline .passmcp/baseline.json

A pulse is deliberately small -- connect, list the catalogue, hash it,
compare -- because a watcher that re-ran nine phases on a loop would be the
abusive client passmcp warns everyone else about. Two requests and a string
comparison, every few minutes, and a timer in between.

Every pulse is also timed and its outcome classed as ok, protocol_error,
transport_error, auth_error or timeout, with a narrower error kind such as
connection_refused. That costs no extra request. When the watch ends it
prints the availability: pulses answered, p50/p95/p99 latency of the
answered ones, the worst run of consecutive failures and a breakdown by
error kind. --output ndjson streams one event per pulse and ends with a
summary event; --output json prints one document when the watch ends.

  --once takes a single pulse and exits, which is the shape a CI job
  wants: exit 2 when the catalogue is not the approved one, 0 when it is,
  and 1 when passmcp never got an answer at all.

Severity is by kind rather than by count. A readOnlyHint becoming true
after approval is critical, because it is the flip that makes a cautious
client start invoking a tool it previously refused. A new optional
property is noise, and is reported as such.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runWatch,
}

// runWatch is the watch command.
func runWatch(cmd *cobra.Command, args []string) error {
	spec, approved, err := watchSetup(cmd, args)
	if err != nil {
		return err
	}

	// Ctrl-C stops the watcher rather than killing it: a long-lived
	// process should say how far it got.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := newWatchWriter(spec.Output.Format, os.Stdout)
	res, err := watch.Run(ctx, watch.Options{
		Spec:     spec,
		Approved: approved,
		Interval: watchInterval,
		Once:     watchOnce,
		Version:  Version,
		Sink:     out.event,
	})
	if err != nil {
		return err
	}
	if err := out.finish(res); err != nil {
		return err
	}
	if err := approveWatched(res); err != nil {
		return err
	}

	// A single pulse that got no answer is not a verdict either way: the
	// documented exit for "passmcp never got an answer at all" is 1.
	if watchOnce && res.Summary.OK == 0 {
		return fmt.Errorf("watch: the server did not answer: %s", out.lastErr)
	}
	// The exit code is the gate. A watcher that saw a change and
	// returned zero would be a gate that never fails.
	if res.Drifted && !approveBaseline {
		osExit(2)
	}
	return nil
}

// watchSetup resolves what to watch and what it is compared against.
func watchSetup(cmd *cobra.Command, args []string) (engine.RunSpec, *baseline.Snapshot, error) {
	target, err := resolveTarget(cmd, args)
	if err != nil {
		return engine.RunSpec{}, nil, err
	}
	spec, err := buildSpec(target, nil)
	if err != nil {
		return engine.RunSpec{}, nil, err
	}
	if strings.TrimSpace(baselineFile) == "" {
		return engine.RunSpec{}, nil, errors.New("watch needs --baseline: there is nothing to compare against. " +
			"Run `passmcp check <target> --baseline <file> --approve` first")
	}
	approved, err := baseline.Load(baselineFile)
	if err != nil {
		return engine.RunSpec{}, nil, err
	}
	return spec, approved, nil
}

// approveWatched promotes what the watch saw, when --approve asked for it.
func approveWatched(res *watch.Result) error {
	if !approveBaseline || res.Latest == nil {
		return nil
	}
	if err := baseline.Save(baselineFile, *res.Latest); err != nil {
		return err
	}
	diag.Infof("approved %d tool(s) as the new baseline in %s", len(res.Latest.Tools), baselineFile)
	return nil
}

// maxWatchJSONEvents bounds the events --output json keeps for its single
// document. A watcher can run for months; the document it prints at the
// end must not grow with it. NDJSON streams, so it has no such bound.
const maxWatchJSONEvents = 1000

// watchWriter renders events in the selected output format. Everything
// it writes goes to stdout, because the events are the output; nothing
// here is a diagnostic.
type watchWriter struct {
	format engine.Format
	w      io.Writer
	enc    *json.Encoder
	// events and dropped are the --output json document's body.
	events  []watch.Event
	dropped int
	// lastErr is the most recent failed pulse's error, for the exit
	// message of a --once that got no answer.
	lastErr string
}

// newWatchWriter writes format to w. The text form goes through termsafe,
// because an event quotes the server's errors and tool names and is read
// on a terminal; the JSON forms are encoded, which escapes, and are owed
// exactly what the server said.
func newWatchWriter(format engine.Format, w io.Writer) *watchWriter {
	return &watchWriter{format: format, w: termsafe.NewWriter(w), enc: json.NewEncoder(w)}
}

// event handles one event as it happens.
func (ww *watchWriter) event(ev watch.Event) {
	if ev.Kind == "error" {
		ww.lastErr = ev.Err
	}
	switch ww.format {
	case engine.FormatNDJSON:
		_ = ww.enc.Encode(ev)
	case engine.FormatJSON:
		if len(ww.events) == maxWatchJSONEvents {
			ww.events = append(ww.events[:0], ww.events[1:]...)
			ww.dropped++
		}
		ww.events = append(ww.events, ev)
	default:
		writeWatchEvent(ww.w, ev)
	}
}

// watchDocument is --output json: one document, written when the watch
// ends.
type watchDocument struct {
	Target        string        `json:"target"`
	Events        []watch.Event `json:"events"`
	DroppedEvents int           `json:"dropped_events,omitempty"`
	Summary       watch.Summary `json:"summary"`
}

// finish writes the run's summary: the last NDJSON line, the JSON
// document, or the closing lines of the text form.
func (ww *watchWriter) finish(res *watch.Result) error {
	ev := res.SummaryEvent(time.Now().UTC())
	switch ww.format {
	case engine.FormatNDJSON:
		return ww.enc.Encode(ev)
	case engine.FormatJSON:
		ww.enc.SetIndent("", "  ")
		return ww.enc.Encode(watchDocument{Target: res.Target, Events: ww.events, DroppedEvents: ww.dropped, Summary: res.Summary})
	default:
		writeWatchSummary(ww.w, ev)
		return nil
	}
}

// writeWatchEvent prints one event for a person.
func writeWatchEvent(w io.Writer, ev watch.Event) {
	stamp := ev.At.Format("15:04:05")
	switch ev.Kind {
	case "drift":
		_, _ = fmt.Fprintf(w, "%s  drift  %s — %s in %s\n", stamp, ev.Target, ev.Detail, formatMS(ev.LatencyMS))
		writeWatchChanges(w, ev.Changes)
	case "error":
		_, _ = fmt.Fprintf(w, "%s  error  %s — [%s/%s] %s (after %s)\n", stamp, ev.Target, ev.Status, ev.ErrorKind, ev.Detail, formatMS(ev.LatencyMS))
	case "settled":
		_, _ = fmt.Fprintf(w, "%s  stop   %s\n", stamp, ev.Detail)
	default:
		_, _ = fmt.Fprintf(w, "%s  ok     %s — %s in %s\n", stamp, ev.Target, ev.Detail, formatMS(ev.LatencyMS))
	}
}

// writeWatchChanges lists the first few changes of a drift.
func writeWatchChanges(w io.Writer, changes []baseline.Change) {
	shown := min(len(changes), 5)
	for i := range shown {
		c := changes[i]
		_, _ = fmt.Fprintf(w, "           [%s] %s: %s\n", c.Severity, c.Tool, c.Detail)
		if c.Was != "" || c.Now != "" {
			_, _ = fmt.Fprintf(w, "               was %q\n               now %q\n", c.Was, c.Now)
		}
	}
	if len(changes) > shown {
		_, _ = fmt.Fprintf(w, "           and %d more\n", len(changes)-shown)
	}
}

// writeWatchSummary prints the run's availability for a person.
func writeWatchSummary(w io.Writer, ev watch.Event) {
	s := ev.Summary
	_, _ = fmt.Fprintf(w, "%s  summary %s — %s\n", ev.At.Format("15:04:05"), ev.Target, s.Sentence())
	_, _ = fmt.Fprintf(w, "           latency p50 %s  p95 %s  p99 %s over %d answered pulse(s)\n",
		formatMS(s.Latency.P50), formatMS(s.Latency.P95), formatMS(s.Latency.P99), s.Latency.Samples)
	_, _ = fmt.Fprintf(w, "           worst failure streak %d\n", s.WorstFailureStreak)
	if len(s.ByErrorKind) > 0 {
		_, _ = fmt.Fprintf(w, "           errors %s\n", errorBreakdown(s.ByErrorKind))
	}
}

// errorBreakdown lists error kinds, most frequent first.
func errorBreakdown(kinds map[string]int) string {
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if kinds[names[i]] != kinds[names[j]] {
			return kinds[names[i]] > kinds[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf("%s ×%d", k, kinds[k])
	}
	return strings.Join(parts, ", ")
}

// formatMS renders milliseconds with a decimal only where it matters.
func formatMS(ms float64) string {
	if ms < 10 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.0fms", ms)
}

func init() {
	// The same flag sets check uses. A watch is a loop around the same
	// target, the same credentials and the same policy, so it has to be
	// described the same way -- a second vocabulary for the same facts is
	// how two surfaces start disagreeing about what they were pointed at.
	watchCmd.Flags().AddFlagSet(targetFlags())
	watchCmd.Flags().AddFlagSet(credFlags())
	watchCmd.Flags().AddFlagSet(policyFlags())
	watchCmd.Flags().AddFlagSet(paceFlags())
	watchCmd.Flags().AddFlagSet(outputFlags())

	watchCmd.Flags().DurationVar(&watchInterval, "interval", watch.DefaultInterval,
		"how long to wait between pulses")
	watchCmd.Flags().BoolVar(&watchOnce, "once", false,
		"take a single pulse and exit; exit 2 when the catalogue is not the approved one")
}
