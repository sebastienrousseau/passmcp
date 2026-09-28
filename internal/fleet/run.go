// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/policy"
	"satellion.com/passmcp/internal/telemetry"
)

// Status is how one server came out of a fleet run.
type Status string

// Server statuses. Unreachable is never a pass and never "unchanged": a
// server nobody could reach has told the fleet nothing about itself.
const (
	StatusPass        Status = "pass"
	StatusFail        Status = "fail"
	StatusUnreachable Status = "unreachable"
)

// Exit statuses, as `passmcp check` uses them: 2 for a verdict that fails the
// gate, 1 for a run that could not be made.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitFailed      = 2
	summaryFileName = "summary.json"
	latestFileName  = "latest.json"
	runsDirName     = "runs"
	attestationFile = "attestation.json"
	catalogueFile   = "catalogue.json"
	diffFile        = "diff.json"
)

// Runner runs a fleet.
type Runner struct {
	// Version is passmcp's own version, carried into every attestation.
	Version string
	// StateDir is where runs are kept, one directory per server.
	StateDir string
	// BaseDir resolves the relative policy paths in the fleet file.
	BaseDir string
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Check runs one server. Nil means engine.Run.
	Check func(ctx context.Context, spec engine.RunSpec) *engine.Result
	// Customise adjusts each server's spec before it runs; tests use it to
	// shorten a run.
	Customise func(*engine.RunSpec)
	// Progress, when set, is told about each server as it finishes.
	Progress func(ServerResult)
}

// ServerResult is one server's line in the summary.
type ServerResult struct {
	Name     string  `json:"name"`
	Endpoint string  `json:"endpoint"`
	Status   Status  `json:"status"`
	Exit     int     `json:"exit"`
	Score    float64 `json:"score"`
	Grade    string  `json:"grade"`
	// Error is why the server could not be checked, for an unreachable one.
	Error string `json:"error,omitempty"`
	// Attestation is the digest of the statement this run wrote.
	Attestation string `json:"attestation,omitempty"`
	// Previous is the digest of the statement the run was compared with.
	Previous string `json:"previous_attestation,omitempty"`
	// Changes is what differs from the previous run, worst first.
	Changes []Change `json:"changes"`
	// Worst is the highest severity among Changes.
	Worst string `json:"worst_change,omitempty"`
	// Critical is true when any change is critical, which fails the fleet
	// whatever the score says.
	Critical bool `json:"critical"`
	// Dir is where this run's evidence was written.
	Dir string `json:"dir,omitempty"`
}

// Summary is a whole fleet run.
type Summary struct {
	Started time.Time      `json:"started"`
	Servers []ServerResult `json:"servers"`
	Exit    int            `json:"exit"`
}

// Run checks every server in the fleet, writes an attestation for each,
// compares each with its previous run and writes the summary.
func (r Runner) Run(ctx context.Context, f *File) (*Summary, error) {
	if err := os.MkdirAll(r.StateDir, 0o750); err != nil {
		return nil, err
	}
	sum := &Summary{Started: r.now(), Servers: []ServerResult{}}
	for _, s := range f.Servers {
		res := r.runOne(ctx, f, s)
		sum.Servers = append(sum.Servers, res)
		if r.Progress != nil {
			r.Progress(res)
		}
	}
	sum.Exit = exitOf(sum.Servers)
	if err := writeJSON(filepath.Join(r.StateDir, summaryFileName), sum); err != nil {
		return sum, err
	}
	return sum, nil
}

// exitOf is the fleet's exit status: a failed gate or a critical change
// outranks an unreachable server, which outranks a clean run.
func exitOf(servers []ServerResult) int {
	exit := ExitOK
	for _, s := range servers {
		if s.Exit == ExitFailed {
			return ExitFailed
		}
		if s.Exit == ExitError {
			exit = ExitError
		}
	}
	return exit
}

// runOne checks one server and records the outcome.
func (r Runner) runOne(ctx context.Context, f *File, s Server) ServerResult {
	red := redactorFor(s)
	out := ServerResult{Name: s.Name, Endpoint: red.URL(s.target()), Changes: []Change{}}
	spec, err := r.specFor(f, s)
	if err != nil {
		return unreachable(out, red, err)
	}
	res := r.check(ctx, spec)
	if res.Err != nil || res.Report == nil {
		cause := res.Err
		if cause == nil {
			cause = errors.New("the run produced no report")
		}
		return unreachable(out, red, cause)
	}
	// A server that never completed a handshake told the fleet nothing about
	// itself: its catalogue and verdicts are absent, not changed.
	if res.Session == nil || !res.Session.Reached {
		return unreachable(out, red, notReached(res))
	}
	out.Endpoint = res.Report.Target.Endpoint
	out.Score, out.Grade = res.Report.Score.Total, res.Report.Score.Grade
	out.Status, out.Exit = StatusPass, ExitOK
	if res.Failed() {
		out.Status, out.Exit = StatusFail, ExitFailed
	}
	if err := r.record(spec, res, red, &out); err != nil {
		return unreachable(out, red, fmt.Errorf("recording the run: %w", err))
	}
	if out.Critical {
		out.Exit = ExitFailed
	}
	return out
}

// notReached says why a run never completed a handshake: the reason the run
// was blocked, else the first failing connectivity finding.
func notReached(res *engine.Result) error {
	cause := firstFailure(res)
	switch {
	case res.Report.Blocked != "" && cause != "":
		// The blocked reason says what could not happen; the failing
		// finding says why, which is what an operator acts on.
		return fmt.Errorf("%s (%s)", res.Report.Blocked, cause)
	case res.Report.Blocked != "":
		return errors.New(res.Report.Blocked)
	case cause != "":
		return errors.New(cause)
	}
	return errors.New("the server never completed an MCP handshake")
}

// firstFailure is the first failing finding, as "id: detail".
func firstFailure(res *engine.Result) string {
	for _, p := range res.Report.Phases {
		for _, f := range p.Findings {
			if f.Status == "fail" {
				return fmt.Sprintf("%s: %s", f.ID, f.Detail)
			}
		}
	}
	return ""
}

// unreachable marks a server that told the fleet nothing about itself.
func unreachable(out ServerResult, red *telemetry.Redactor, err error) ServerResult {
	out.Status, out.Exit = StatusUnreachable, ExitError
	out.Score, out.Grade = 0, ""
	out.Error = red.String(err.Error())
	out.Changes = []Change{}
	return out
}

// record writes the run's evidence, compares it with the previous run and
// moves the server's latest pointer forward.
func (r Runner) record(spec engine.RunSpec, res *engine.Result, red *telemetry.Redactor, out *ServerResult) error {
	serverDir := filepath.Join(r.StateDir, out.Name)
	dir := freshRunDir(filepath.Join(serverDir, runsDirName, r.now().UTC().Format("20060102T150405Z")))
	spec.Output.ReportDir = dir
	if _, err := res.WriteDir(spec, r.Version); err != nil {
		return err
	}
	snap := snapshotOf(res, red)
	if err := writeJSON(filepath.Join(dir, catalogueFile), snap); err != nil {
		return err
	}
	digest, err := fileDigest(filepath.Join(dir, attestationFile))
	if err != nil {
		return err
	}
	out.Dir, out.Attestation = dir, digest

	prev, err := loadLatest(serverDir)
	if err != nil {
		return err
	}
	if prev != nil {
		out.Previous = prev.Attestation
		changes, err := compareRuns(prev, dir, red)
		if err != nil {
			return err
		}
		out.Changes = changes
		out.Worst, out.Critical = worstOf(changes)
	}
	if err := writeJSON(filepath.Join(dir, diffFile), out); err != nil {
		return err
	}
	return writeJSON(filepath.Join(serverDir, latestFileName), latest{Dir: dir, Attestation: digest})
}

// freshRunDir is dir, or dir with a counter when a run in the same second
// already took it: a second run must never overwrite the one it is compared
// against.
func freshRunDir(dir string) string {
	for i, d := 2, dir; ; i++ {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return d
		}
		d = fmt.Sprintf("%s-%d", dir, i)
	}
}

// latest points at a server's most recent recorded run.
type latest struct {
	Dir         string `json:"dir"`
	Attestation string `json:"attestation"`
}

// loadLatest reads a server's pointer, or nil when it has never been run.
func loadLatest(serverDir string) (*latest, error) {
	b, err := os.ReadFile(filepath.Join(serverDir, latestFileName)) // #nosec G304 -- under the operator's state directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var l latest
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", latestFileName, err)
	}
	return &l, nil
}

// snapshotOf is the catalogue the run saw, with secrets masked: tool text
// comes from the server, and the endpoint can carry a token in its query.
func snapshotOf(res *engine.Result, red *telemetry.Redactor) baseline.Snapshot {
	var snap baseline.Snapshot
	if res.Session != nil && res.Session.Snapshot != nil {
		snap = *res.Session.Snapshot
	} else {
		snap = baseline.Take("", nil)
	}
	snap.Endpoint = red.URL(snap.Endpoint)
	b, err := json.Marshal(snap)
	if err != nil {
		return snap
	}
	var masked baseline.Snapshot
	if json.Unmarshal([]byte(red.String(string(b))), &masked) != nil {
		return snap
	}
	return masked
}

// specFor builds the run for one server.
func (r Runner) specFor(f *File, s Server) (engine.RunSpec, error) {
	spec := engine.RunSpec{
		Version: r.Version,
		Target:  engine.TargetSpec{Endpoint: s.Endpoint},
		Creds:   credSpecFor(s.Credential),
		Output:  engine.OutputSpec{Format: engine.FormatJSON, NoColor: true},
	}
	if len(s.Command) > 0 {
		spec.Target = engine.TargetSpec{Command: s.Command[0], Args: s.Command[1:]}
	}
	if err := applyPacing(&spec, f.Pacing); err != nil {
		return spec, err
	}
	if s.Policy != "" {
		p, err := policy.Load(r.resolve(s.Policy))
		if err != nil {
			return spec, err
		}
		spec.Gate = p
	}
	if r.Customise != nil {
		r.Customise(&spec)
	}
	return spec.WithDefaults(), nil
}

// applyPacing copies the fleet's pacing onto a run.
func applyPacing(spec *engine.RunSpec, p Pacing) error {
	spec.Pacing = engine.PacingSpec{RPS: engine.DefaultRPS, Samples: p.Samples, Concurrency: p.Concurrency}
	if p.RPS != nil {
		spec.Pacing.RPS = *p.RPS
	}
	if p.CallTimeout != "" {
		d, err := time.ParseDuration(p.CallTimeout)
		if err != nil {
			return err
		}
		spec.Pacing.CallTimeout = d
	}
	return nil
}

// credSpecFor turns a credential reference into the engine's form. The
// engine reads the named variables itself and registers their values with
// the run's redactor before the first request.
func credSpecFor(c *Credential) engine.CredSpec {
	if c == nil {
		return engine.CredSpec{Mode: "none"}
	}
	return engine.CredSpec{
		Mode:            c.mode(),
		TokenEnv:        c.TokenEnv,
		ClientID:        c.ClientID,
		ClientSecretEnv: c.ClientSecretEnv,
		TokenURL:        c.TokenURL,
		Scope:           c.Scope,
	}
}

// redactorFor knows every secret the fleet file points at, so the summary,
// the diffs and the logs mask them as the engine masks its own output.
func redactorFor(s Server) *telemetry.Redactor {
	red := &telemetry.Redactor{}
	if c := s.Credential; c != nil {
		for _, name := range []string{c.TokenEnv, c.ClientSecretEnv} {
			if name != "" {
				red.Add(os.Getenv(name))
			}
		}
	}
	return red
}

// target is what the entry names, for a server that never answered.
func (s Server) target() string {
	if len(s.Command) > 0 {
		return strings.Join(s.Command, " ")
	}
	return s.Endpoint
}

// resolve makes a fleet-relative path absolute.
func (r Runner) resolve(p string) string {
	if filepath.IsAbs(p) || r.BaseDir == "" {
		return p
	}
	return filepath.Join(r.BaseDir, p)
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Runner) check(ctx context.Context, spec engine.RunSpec) *engine.Result {
	if r.Check != nil {
		return r.Check(ctx, spec)
	}
	return engine.Run(ctx, spec, nil)
}

// fileDigest is the sha256 of a file, in the form attestations cite.
func fileDigest(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a file this run just wrote
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// writeJSON writes v indented, readable only by the operator.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
