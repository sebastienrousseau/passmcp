// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/tui"
	"satellion.com/passmcp/trace"
)

var checkCmd = &cobra.Command{
	Use:   "check <endpoint>",
	Short: "Test an MCP server and explain, in plain language, whether it is ready for agents.",
	Long: `Test an MCP server end to end and report, in plain language, whether
agents can use it and what to improve.

passmcp runs nine checks: it reaches the server, learns how it wants to be
authorized, signs in with the credentials you give it, completes the MCP
handshake, probes protocol behaviour, reads the tool and resource catalog,
safely calls what it can, measures speed under load, and confirms recovery
after a dropped session.

Only read-only tools are called unless you pass --allow-mutations or
--allow-destructive. Requests are throttled to --rps.

Examples:
  passmcp check https://mcp.example.com/mcp
  passmcp check https://mcp.example.com/mcp --token-env MCP_TOKEN
  passmcp check https://mcp.example.com/mcp --auth client-credentials \
      --client-id acme --client-secret-env ACME_SECRET --param profile_id=tenant-1
  passmcp check https://mcp.example.com/mcp --report-dir ./out --verbose
  passmcp check --profile prod --output json > report.json

Most MCP servers are programs rather than URLs. Point passmcp at one with
--stdio and the command after --; passmcp starts it, diagnoses it, and stops
it again:

  passmcp check --stdio -- npx -y @modelcontextprotocol/server-everything
  passmcp check --stdio --stdio-env GITHUB_TOKEN -- docker run -i --rm ghcr.io/example/mcp

The server gets a fixed base environment plus whatever --stdio-env names,
and nothing else: it is a program nobody has audited, and everything else
you have exported is somebody else's secret.`,
	// Not MaximumNArgs(1): with --stdio the command to run follows "--",
	// and the count is whatever that command needs. resolveTarget rejects
	// the combinations that are genuinely wrong, with a reason.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCheck(cmd, args, nil)
	},
}

func init() {
	checkCmd.Flags().AddFlagSet(targetFlags())
	checkCmd.Flags().AddFlagSet(credFlags())
	checkCmd.Flags().AddFlagSet(policyFlags())
	checkCmd.Flags().AddFlagSet(paceFlags())
	checkCmd.Flags().AddFlagSet(outputFlags())
}

// runCheck is shared by check, connect and tools; only restricts phases.
//
// Everything this function does after building the spec is presentation:
// the live view, the interactive selector, where the bytes go. The run
// itself belongs to the engine, which is what lets the TUI and the web UI
// start exactly the same run without reimplementing any of it.
func runCheck(cmd *cobra.Command, args []string, only []string) error {
	ctx := cmdContext(cmd)
	spec, cr, err := prepareCheck(cmd, args, only)
	if err != nil {
		return err
	}

	isTTY := spec.Output.Format == engine.FormatText && stdoutIsTTY()

	// -i: pick the tools to exercise before anything runs. Drawing the
	// selector is this surface's job; what it produces is the engine's,
	// so the widening a deliberate choice implies happens in one place.
	if spec.Output.Interactive && isTTY {
		stop, err := selectTools(ctx, &spec)
		if stop || err != nil {
			return err
		}
	}

	// NDJSON streams events as they land, so it is wired to the sink
	// rather than printed at the end.
	var ndjson *json.Encoder
	if spec.Output.Format == engine.FormatNDJSON {
		ndjson = json.NewEncoder(os.Stdout)
	}

	// The live view: a calm checklist that updates in place while the run
	// proceeds, printed inline so the finished list stays above the report.
	// Quitting mid-run cancels the run.
	var program *tea.Program
	var runView *tui.RunModel
	runCtx, cancelRun := context.WithCancel(ctx)
	// Settle the run's trace id here rather than letting probe.Run generate
	// one, so the structured diagnostics carry the same id as the report
	// and the exported spans. trace.Ensure keeps an id the caller already
	// set, so nothing downstream changes.
	runCtx = trace.Ensure(runCtx)
	diag.SetRunID(trace.FromContext(runCtx))
	defer cancelRun()
	if isTTY {
		runView, program = newRunView(spec, cr, cancelRun)
	}

	res, stop := executeCheck(runCtx, spec, checkSink(spec, program, ndjson), program, runView)
	if stop || res == nil || res.Report == nil {
		return resultErr(res)
	}
	return finishCheck(runCtx, spec, res, ndjson)
}

// prepareCheck resolves the target, builds and validates the run's spec,
// and loads the credentials it names.
func prepareCheck(cmd *cobra.Command, args []string, only []string) (engine.RunSpec, *creds.Credentials, error) {
	target, err := resolveTarget(cmd, args)
	if err != nil {
		return engine.RunSpec{}, nil, err
	}
	spec, err := buildSpec(target, only)
	if err != nil {
		return engine.RunSpec{}, nil, err
	}
	if err := spec.Validate(); err != nil {
		return engine.RunSpec{}, nil, err
	}
	cr, err := spec.Credentials()
	if err != nil {
		return engine.RunSpec{}, nil, err
	}

	diag.Debugf("passmcp %s → %s", Version, spec.Target.Describe())
	diag.Debugf("credentials: %s", cr.Describe())
	for f, src := range cr.Sources {
		diag.Debugf("credential %s from %s", f, src)
	}
	return spec, cr, nil
}

// selectTools draws the interactive selector and narrows spec to the
// tools picked. stop is true when there is nothing to run: the selector
// was dismissed, or nothing was selected.
func selectTools(ctx context.Context, spec *engine.RunSpec) (stop bool, err error) {
	tui.Version = Version
	items, ok, err := runSelector(ctx, func() ([]tui.Item, error) {
		return selectorItems(ctx, *spec)
	})
	if err != nil {
		return true, err
	}
	if !ok {
		return true, nil
	}
	if len(items) == 0 {
		fmt.Println("No tools selected.")
		return true, nil
	}
	names := make([]string, 0, len(items))
	kinds := make(map[string]string, len(items))
	for _, it := range items {
		names = append(names, it.Name)
		kinds[it.Name] = it.Kind
	}
	spec.SelectTools(names, kinds)
	return false, nil
}

// newRunView builds the live checklist for a terminal run; quitting it
// cancels the run.
func newRunView(spec engine.RunSpec, cr *creds.Credentials, cancelRun context.CancelFunc) (*tui.RunModel, *tea.Program) {
	tui.Version = Version
	var phases []tui.Phase
	for _, name := range spec.PhaseNames() {
		phases = append(phases, tui.Phase{Name: name, Title: probe.PhaseTitle(name)})
	}
	runView := tui.NewRunModel(spec.Target.Describe(), runSubtitle(cr), phases)
	runView.Cancel = cancelRun
	return runView, newProgram(runView)
}

// checkSink routes the engine's events to the debug log, the live view and
// the NDJSON stream, whichever of them this run has.
func checkSink(spec engine.RunSpec, program *tea.Program, ndjson *json.Encoder) engine.SinkFunc {
	return engine.SinkFunc(func(e engine.Event) {
		switch e.Kind {
		case engine.EventPhaseStart:
			diag.Debugf("phase %s starting", e.Phase)
			if program != nil {
				program.Send(tui.PhaseStartMsg{Name: e.Phase})
			}
			if ndjson != nil {
				_ = ndjson.Encode(map[string]any{"type": "phase", "phase": e.Phase})
			}
		case engine.EventFinding:
			f := e.Finding
			diag.Debugf("%s %s: %s — %s", f.Status, f.ID, f.Title, f.Detail)
			if ndjson != nil {
				_ = ndjson.Encode(map[string]any{"type": "finding", "finding": f})
			}
		case engine.EventPhaseDone:
			reportPhase(*e.Result, program, spec.Output.Format)
		case engine.EventRequest:
			if ndjson != nil {
				_ = ndjson.Encode(map[string]any{"type": "request", "event": e.Request})
			}
		}
	})
}

// executeCheck runs the engine, beside the live view when there is one.
// stop is true when the person quit the live view mid-run.
func executeCheck(runCtx context.Context, spec engine.RunSpec, sink engine.Sink, program *tea.Program, runView *tui.RunModel) (res *engine.Result, stop bool) {
	if program == nil {
		return engine.Run(runCtx, spec, sink), false
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		res = engine.Run(runCtx, spec, sink)
		program.Send(tui.DoneMsg{})
	}()
	if _, err := program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	program.Kill()
	<-done
	return res, runView != nil && runView.Aborted()
}

// resultErr is the error a run ended with, if it got as far as having one.
func resultErr(res *engine.Result) error {
	if res != nil {
		return res.Err
	}
	return nil
}

// finishCheck does everything after a run that produced a report: the
// baseline, the saved files, the report itself, the gate's verdict and the
// trace export, then the exit status.
func finishCheck(runCtx context.Context, spec engine.RunSpec, res *engine.Result, ndjson *json.Encoder) error {
	if err := approveRun(res); err != nil {
		return err
	}
	if err := emitReport(spec, res, ndjson); err != nil {
		return err
	}
	// The policy's answer, after the report it judged. On stdout when the
	// report was prose a person is reading; on stderr otherwise, because a
	// gate verdict appended to JSON or SARIF would make the document
	// unparseable, and the one reader who needs it there is a CI log.
	if res.Gate != nil {
		dst := os.Stdout
		if spec.Output.Format != engine.FormatText && spec.Output.Format != engine.FormatMD {
			dst = os.Stderr
		}
		writePolicyResult(dst, *res.Gate)
	}

	// After the report, and never fatal. A collector being unreachable is
	// not a finding about the server under test, and a run that produced a
	// verdict must not be reported as a run that failed to.
	if err := res.ExportTraces(runCtx, spec, Version); err != nil {
		diag.Warnf("OTLP export failed: %v", err)
	} else if spec.Output.OTLPEndpoint != "" {
		diag.Infof("exported the run to %s", spec.Output.OTLPEndpoint)
	}
	exportOCSF(runCtx, spec, res)

	if res.Err != nil {
		return res.Err
	}
	if res.Failed() {
		osExit(2)
	}
	return nil
}

// exportOCSF posts the OCSF events when --ocsf-endpoint named a destination,
// saying where they are going before anything leaves, as --osv does. Never
// fatal, for the same reason the trace export is not: a SIEM being
// unreachable is not a finding about the server.
func exportOCSF(ctx context.Context, spec engine.RunSpec, res *engine.Result) {
	if spec.Output.OCSFEndpoint == "" || res.Report == nil {
		return
	}
	diag.Infof("sending %d OCSF event(s) to %s (--ocsf-endpoint); nothing else leaves this machine",
		len(res.OCSFEvents()), spec.Output.OCSFEndpoint)
	if err := res.ExportOCSF(ctx, spec); err != nil {
		diag.Warnf("OCSF export failed: %v", err)
	}
}

// approveRun writes what the run saw as the new baseline when --approve
// asked for it.
func approveRun(res *engine.Result) error {
	// --approve promotes what this run saw, after the report so the person
	// approving has just read what they are approving. Written even when
	// findings failed: approving a catalogue is a statement about drift,
	// not about quality, and conflating the two would make the gate
	// unusable on a server with a known, accepted failing check.
	if !approveBaseline {
		return nil
	}
	if res.Session == nil || res.Session.Snapshot == nil {
		diag.Warnf("nothing to approve: the run did not reach the catalogue")
	} else if err := baseline.Save(baselineFile, *res.Session.Snapshot); err != nil {
		return err
	} else {
		diag.Infof("approved %d tool(s) as the baseline in %s",
			len(res.Session.Snapshot.Tools), baselineFile)
	}
	return nil
}

// emitReport saves the report directory when one was asked for, then
// writes the report to stdout in the selected format.
func emitReport(spec engine.RunSpec, res *engine.Result, ndjson *json.Encoder) error {
	if spec.Output.ReportDir != "" {
		if _, err := res.WriteDir(spec, Version); err != nil {
			return err
		}
		diag.Infof("saved the full report and telemetry to %s", spec.Output.ReportDir)
	}
	if spec.Output.Format == engine.FormatNDJSON {
		rep := *res.Report
		rep.Events = nil
		_ = ndjson.Encode(map[string]any{"type": "report", "report": rep})
		return nil
	}
	width := 0
	if spec.Output.Format == engine.FormatText {
		width = termWidth()
	}
	out := spec
	out.Output.NoColor = spec.Output.NoColor || !stdoutIsTTY()
	return res.Render(os.Stdout, out, width)
}

// reportPhase draws one finished phase, in whichever way this surface is
// currently speaking.
func reportPhase(pr probe.PhaseResult, program *tea.Program, format engine.Format) {
	var ok, warn, fail int
	for _, f := range pr.Findings {
		switch f.Status {
		case probe.Fail:
			fail++
		case probe.Warn:
			warn++
		case probe.Pass, probe.Info:
			ok++
		}
	}
	counts := fmt.Sprintf("%d ok", ok)
	if warn > 0 {
		counts += fmt.Sprintf(", %d warn", warn)
	}
	if fail > 0 {
		counts += fmt.Sprintf(", %d fail", fail)
	}
	action := strings.ToUpper(string(pr.Status))
	if pr.Skipped != "" {
		counts = "skipped: " + pr.Skipped
	} else if pr.Status == probe.Skip {
		for _, f := range pr.Findings {
			if f.Status == probe.Skip && f.Detail != "" {
				counts = f.Detail
				break
			}
		}
	}
	switch {
	case program != nil:
		program.Send(tui.PhaseDoneMsg{Name: pr.Name, Action: action, Duration: pr.Duration.Duration(), Message: phaseSummary(pr, warn, fail)})
	case format == engine.FormatText:
		log.Printf("%s [%s] %s: %s", tui.ResultIcon(action), action, pr.Name, counts)
	default:
		diag.Infof("%-12s %-4s %7s  %s", pr.Name, action, pr.Duration.Duration().Round(time.Millisecond), counts)
	}
}

// runSubtitle is the one-line, secret-free description of the credentials,
// for the live view.
func runSubtitle(cr *creds.Credentials) string {
	switch cr.Effective() {
	case creds.ModeBearer:
		return "signing in with a bearer token"
	case creds.ModeClientCredentials:
		return "signing in with OAuth client credentials"
	case creds.ModeAuthorizationCode:
		return "signing in with your stored login"
	}
	return "no credentials"
}

// phaseSummary turns a finished phase into a short, human status line.
func phaseSummary(pr probe.PhaseResult, warn, fail int) string {
	switch {
	case pr.Skipped != "":
		return "not needed"
	case pr.Status == probe.Skip:
		for _, f := range pr.Findings {
			if f.Status == probe.Skip && f.Detail != "" {
				return f.Detail
			}
		}
		return "not needed"
	case fail == 1:
		return "1 problem"
	case fail > 1:
		return fmt.Sprintf("%d problems", fail)
	case warn == 1:
		return "1 thing to improve"
	case warn > 1:
		return fmt.Sprintf("%d things to improve", warn)
	default:
		for _, f := range pr.Findings {
			if (f.Status == probe.Pass || f.Status == probe.Info) && f.Detail != "" {
				return f.Detail
			}
		}
		return "looks good"
	}
}

// termWidth returns stdout's column count, clamped to a comfortable reading
// width, or 84 when stdout is not a terminal.
func termWidth() int {
	if f, ok := any(os.Stdout).(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 40 {
			if w > 96 {
				return 96
			}
			return w
		}
	}
	return 84
}

// selectorItems asks the engine what the selector should offer, and
// renders it in the terminal's terms.
//
// Connecting, listing and classifying moved to engine.ListToolChoices so
// the browser can offer the same list; what stays here is the conversion
// into the TUI's own row type, which is the only part that is genuinely
// this surface's business.
func selectorItems(ctx context.Context, spec engine.RunSpec) ([]tui.Item, error) {
	choices, err := engine.ListToolChoices(ctx, spec, Version)
	if err != nil {
		return nil, err
	}
	items := make([]tui.Item, 0, len(choices))
	for _, c := range choices {
		items = append(items, tui.Item{
			Name: c.Name, Kind: c.Kind, Policy: c.Policy, Description: c.Description,
		})
	}
	return items, nil
}

// newProgram builds the live-view program; tests swap in a headless one.
// The view renders inline (no alt-screen) so the finished checklist stays
// in the scrollback above the printed report.
var newProgram = func(m tea.Model) *tea.Program { return tea.NewProgram(m) }

// runSelector is indirected so tests can drive the interactive path.
var runSelector = tui.RunSelector
