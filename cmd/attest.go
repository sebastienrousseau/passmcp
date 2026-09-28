// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/policy"
	"satellion.com/passmcp/internal/report"
)

// A report is a document and an attestation is a claim. `passmcp check
// --output attestation` produces the claim from a live run; these two
// commands are what make it useful afterwards.
//
// `attest` exists separately from the output format because signing usually
// is not the job that ran the diagnostic. A CI pipeline runs passmcp with
// credentials for the server under test, saves the report, and then signs in
// a second job with an OIDC identity and no server credentials at all — the
// same split SLSA provenance uses, and the reason the predicate is derived
// from the report rather than from the session.
//
// `verify` is deliberately not a verdict about the server. It answers
// whether the statement can be believed: that it parses, that its digest
// still covers the target it names, that it says what it was judged against.
// Whether the server is good enough is a separate question, answered by the
// gate flags for a one-off and by --policy for anything an organisation has
// to agree on.

var attestCmd = &cobra.Command{
	Use:   "attest [report.json]",
	Short: "Turn a saved JSON report into an in-toto attestation.",
	Long: `Read a JSON report and write the in-toto statement for it.

The statement is the same one 'passmcp check --output attestation' produces.
It exists as a separate command because the job that signs an attestation
is usually not the job that ran the diagnostic: run passmcp where the server
credentials live, save the report, then attest and sign somewhere that has
an OIDC identity and no access to the server at all.

  passmcp check URL --output json > report.json
  passmcp attest report.json > attestation.json

With no argument, or with -, the report is read from standard input.

Signing is left to the tool your pipeline already trusts, because an
attestation nobody can verify offline is not worth producing:

  cosign attest-blob --predicate attestation.json --new-bundle-format ...

Use 'passmcp verify' to check a statement before acting on it.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := readInput(args)
		if err != nil {
			return err
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			return fmt.Errorf("that is not a passmcp JSON report: %w", err)
		}
		// A report with no target is almost always the wrong file — another
		// tool's JSON, or a report directory's telemetry. Saying so beats a
		// statement whose subject is an empty string.
		if rep.Target.Endpoint == "" {
			return errors.New("that JSON has no target.endpoint: it does not look like a passmcp report")
		}
		st, err := attest.From(&rep)
		if err != nil {
			return err
		}
		out, err := st.Marshal()
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(out)); err != nil {
			return err
		}
		return nil
	},
}

var (
	verifyEndpoint  string
	verifyTransport string
	verifyRequire   []string
	verifyMaxFail   int
	verifyMinScore  float64
	// Its own variable rather than the shared `output`: that one is
	// validated against the report formats and can be set from a config
	// file's defaults, and neither applies to a command that renders a
	// verification rather than a report.
	verifyOutput  string
	verifyPolicy  string
	verifyAgainst string
)

var verifyCmd = &cobra.Command{
	Use:   "verify <attestation.json>",
	Short: "Check an attestation offline, and gate on what it says.",
	Long: `Validate a passmcp attestation. Only --reproduce contacts anything.

By default this answers one question: can the statement be believed? It
parses, its subject digest still covers the target it names, its subject is
named for that same target, and it records what the verdicts were judged
against. That is verification, and it is not the same as approval. A
statement can be perfectly valid and describe a server you would never
route to.

Approval is the flags, and each one is a gate that exits 2 when it is not
met:

  --require ID      the named check must have passed
  --max-fail N      at most N checks may have failed
  --min-score N     the score must be at least N
  --endpoint URL    the statement must be about this target
  --against FILE    no check may be worse than in this earlier statement

A gate applies because the flag was given, not because of its value:
--max-fail 0 is the strictest form of that gate, and omitting the flag is
how you ask for no gate at all.

  passmcp verify attestation.json --endpoint https://mcp.example.com/mcp \
    --require auth.unauthenticated_tools --max-fail 0

--against compares two statements about the same target, check by check.
Drift is a delta rather than a threshold: a score that did not move can
hide one check that went from pass to fail beside another that went the
other way. Checks that got worse fail the gate; improvements, checks the
later run did not assess, and checks it newly measured are listed. The
score delta is shown only when both were judged under the same rubric.

  passmcp verify today.json --against approved.json

--reproduce repeats the run the statement records and gates on what got
worse since. A live service cannot give the same answer twice, but the
measurement can be made the same way twice, and the difference is drift:

  passmcp verify approved.json --reproduce --endpoint https://mcp.example.com/mcp \
    --token-env MCP_TOKEN

It is the one form of verify that contacts anything, so it runs only
against a target named with --endpoint that the statement covers, and it
takes from the statement only how the server was measured. Credentials
come from this command line, never from the statement, which records no
secret and whose recorded variable names are not read. Permissions such
as --allow-mutations must be given again and must match the recorded run.

For anything an organisation has to agree on, use a file instead:

  passmcp verify attestation.json --policy company.json

A policy is reviewable, it carries exceptions with a reason and an expiry
date, and it is refused rather than partly applied if it was written for a
later passmcp. The same file governs a live run through "passmcp check
--policy", so what gates a pipeline and what a gateway checks months later
cannot drift apart.

Exit status is 0 when every gate is met, 2 when the statement is valid and
a gate is not, and 1 when the statement cannot be believed at all. A
gateway or registry should treat 1 and 2 differently: the first means the
evidence is unusable, the second means the evidence is good and the answer
is no.

Nothing here checks a signature. Verify the envelope with the tool that
produced it (cosign, or your own trust root), then verify what is inside it
with this.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := readInput(args)
		if err != nil {
			return err
		}
		st, err := attest.Parse(b)
		if err != nil {
			return err
		}
		res := gate(st, cmd.Flags())
		if err := assessFramework(st, &res); err != nil {
			return err
		}

		if strings.TrimSpace(verifyAgainst) != "" {
			if err := compareAgainst(st, verifyAgainst, &res); err != nil {
				return err
			}
		}

		if verifyReproduce {
			if err := reproduce(cmd.Context(), st, &res); err != nil {
				return err
			}
		}

		// Applied to the same subject the flags were, so the two cannot
		// disagree about what the statement said.
		if strings.TrimSpace(verifyPolicy) != "" {
			p, err := policy.Load(verifyPolicy)
			if err != nil {
				return err
			}
			r := p.Evaluate(policy.FromStatement(st), time.Now())
			res.Policy = &r
			if !r.OK {
				res.OK = false
			}
		}

		if verifyOutput == "json" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				return err
			}
		} else {
			writeVerification(cmd.OutOrStdout(), res)
			if res.Policy != nil {
				writePolicyResult(cmd.OutOrStdout(), *res.Policy)
			}
		}
		if !res.OK {
			osExit(2)
		}
		return nil
	},
}

// verification is what `passmcp verify` concluded. It is a separate shape from
// the statement on purpose: a consumer scripting against this wants the
// answer, not the evidence it already has on disk.
type verification struct {
	OK      bool   `json:"ok"`
	Subject string `json:"subject"`
	Target  struct {
		Transport string `json:"transport"`
		Endpoint  string `json:"endpoint"`
	} `json:"target"`
	Server       string        `json:"server,omitempty"`
	SpecRevision string        `json:"specRevision,omitempty"`
	Rubric       string        `json:"rubric,omitempty"`
	RanAt        string        `json:"ranAt"`
	Counts       attest.Counts `json:"counts"`
	Score        *attest.Score `json:"score,omitempty"`
	Blocked      string        `json:"blocked,omitempty"`
	// Gates lists every gate that was asked for and whether it held, so a
	// failing run says which condition was not met rather than only that
	// one was not.
	Gates []gateResult `json:"gates,omitempty"`
	// Against is how the statement differs from the earlier one named by
	// --against, when it was given.
	Against *attestation.Delta `json:"against,omitempty"`
	// Reproduced is how a repeat of the recorded run differs from the
	// statement, when --reproduce was given.
	Reproduced *attestation.Delta `json:"reproduced,omitempty"`
	// Policy is the acceptance policy's answer, when --policy was given. A
	// separate field rather than more entries in Gates: a flag is one
	// person's condition on one command line, and a policy is a document
	// with a name, a version and exceptions somebody signed off.
	Policy *policy.Result `json:"policy,omitempty"`
	// Framework is each control of the framework named by --framework,
	// judged from the statement's verdicts alone. It informs; it gates
	// nothing, because "not assessed" is not a failure of the server.
	Framework *frameworkResult `json:"framework,omitempty"`
}

// gateResult is one asked-for condition and its outcome.
type gateResult struct {
	Gate   string `json:"gate"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}

// gate applies whichever conditions were asked for.
//
// Whether a numeric gate applies is read from the flag having been given,
// not from its value. A sentinel would have to be a number outside the
// useful range, and for --max-fail the strictest useful value is 0 while the
// obvious sentinel is -1 — so `--max-fail 0` and "no gate" would sit one
// apart and a typo would silently turn a gate off.
func gate(st *attest.Statement, flags *pflag.FlagSet) verification {
	var v verification
	p := st.Predicate
	v.OK = true
	if len(st.Subject) > 0 {
		v.Subject = st.Subject[0].Digest["sha256"]
	}
	v.Target.Transport = p.Target.Transport
	v.Target.Endpoint = p.Target.Endpoint
	if p.Target.Server != nil {
		v.Server = strings.TrimSpace(p.Target.Server.Name + " " + p.Target.Server.Version)
	}
	v.SpecRevision = p.JudgedAgainst.SpecRevision
	v.Rubric = p.JudgedAgainst.Rubric
	v.RanAt = p.RanAt.UTC().Format("2006-01-02T15:04:05Z")
	v.Counts = p.Counts
	v.Score = p.Score
	v.Blocked = p.Blocked

	add := func(name string, met bool, format string, a ...any) {
		v.Gates = append(v.Gates, gateResult{Gate: name, Met: met, Detail: fmt.Sprintf(format, a...)})
		if !met {
			v.OK = false
		}
	}

	if verifyEndpoint != "" {
		tr := verifyTransport
		if tr == "" {
			tr = "http"
		}
		// Covers recomputes the digest rather than comparing strings, so a
		// statement whose predicate was edited fails here even though it
		// names the right endpoint.
		ok := st.Covers(tr, verifyEndpoint)
		add("endpoint", ok, "the statement is about %s %s; asked for %s %s",
			p.Target.Transport, p.Target.Endpoint, tr, verifyEndpoint)
		if ok {
			v.Gates[len(v.Gates)-1].Detail = fmt.Sprintf("the statement covers %s %s", tr, verifyEndpoint)
		}
	}

	for _, id := range sortedUnique(verifyRequire) {
		vd, err := st.VerdictFor(id)
		switch {
		case errors.Is(err, attest.ErrNoSuchCheck):
			// Absent is not a pass. A statement that never ran the check
			// cannot vouch for it, and treating silence as success is how a
			// gate becomes decoration.
			add("require:"+id, false, "the statement carries no verdict for %s: it was not run", id)
		case err != nil:
			add("require:"+id, false, "%v", err)
		case vd.Status == "pass":
			add("require:"+id, true, "%s passed", id)
		default:
			detail := fmt.Sprintf("%s is %s", id, vd.Status)
			if vd.Severity != "" {
				detail += " (" + vd.Severity + ")"
			}
			add("require:"+id, false, "%s", detail)
		}
	}

	if flags.Changed("max-fail") {
		add("max-fail", p.Counts.Fail <= verifyMaxFail,
			"%d checks failed; at most %d allowed", p.Counts.Fail, verifyMaxFail)
	}

	if flags.Changed("min-score") {
		if p.Score == nil {
			// A run that assessed no category carries no score, and the
			// statement says so by omitting it. Reading a missing score as
			// zero would fail a server for a reason that is about the run
			// rather than about the server.
			add("min-score", false, "the statement carries no score, so %.0f cannot be met", verifyMinScore)
		} else {
			add("min-score", p.Score.Total >= verifyMinScore,
				"score is %.1f (%s); at least %.0f required", p.Score.Total, p.Score.Grade, verifyMinScore)
		}
	}
	return v
}

// compareAgainst adds the drift gate. Two statements about different targets
// are refused rather than compared: the delta between two servers is not
// drift, and presenting it as drift would be the more dangerous mistake.
func compareAgainst(st *attest.Statement, path string, v *verification) error {
	b, err := os.ReadFile(path) // #nosec G304 -- the caller named the file
	if err != nil {
		return err
	}
	earlier, err := attest.Parse(b)
	if err != nil {
		return fmt.Errorf("--against %s: %w", path, err)
	}
	t := st.Predicate.Target
	if !earlier.Covers(t.Transport, t.Endpoint) {
		e := earlier.Predicate.Target
		return fmt.Errorf("--against %s is about %s %s, and this statement is about %s %s; there is no drift between two different servers",
			path, e.Transport, e.Endpoint, t.Transport, t.Endpoint)
	}
	d := attestation.Compare(earlier, st)
	v.Against = &d
	detail := fmt.Sprintf("no check got worse since %s", earlier.Predicate.RanAt.UTC().Format("2006-01-02T15:04:05Z"))
	if d.Regression() {
		detail = fmt.Sprintf("%d check(s) got worse since %s: %s", len(d.Regressed),
			earlier.Predicate.RanAt.UTC().Format("2006-01-02T15:04:05Z"), changeList(d.Regressed))
	}
	v.Gates = append(v.Gates, gateResult{Gate: "against", Met: !d.Regression(), Detail: detail})
	if d.Regression() {
		v.OK = false
	}
	return nil
}

// changeList renders changes as "id pass→fail (major)".
func changeList(cs []attestation.Change) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		from, to := c.From, c.To
		if from == "" {
			from = "absent"
		}
		if to == "" {
			to = "absent"
		}
		s := fmt.Sprintf("%s %s→%s", c.ID, from, to)
		if c.ToSeverity != "" && to == "fail" {
			s += " (" + c.ToSeverity + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// writeVerification prints the human rendering: what the statement is about,
// then every gate, then the answer.
func writeVerification(w io.Writer, v verification) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

	p("statement  %s %s\n", v.Target.Transport, v.Target.Endpoint)
	if v.Server != "" {
		p("server     %s\n", v.Server)
	}
	if v.SpecRevision != "" {
		p("revision   %s\n", v.SpecRevision)
	}
	p("ran at     %s\n", v.RanAt)
	p("verdicts   %d pass, %d warn, %d fail, %d skip, %d info\n",
		v.Counts.Pass, v.Counts.Warn, v.Counts.Fail, v.Counts.Skip, v.Counts.Info)
	if v.Score != nil {
		p("score      %.1f (%s), rubric %s\n", v.Score.Total, v.Score.Grade, v.Rubric)
	}
	if v.Blocked != "" {
		p("blocked    %s\n", v.Blocked)
	}
	if d := v.Against; d != nil {
		p("\nagainst the earlier statement\n")
		for _, row := range []struct {
			label string
			cs    []attestation.Change
		}{
			{"worse", d.Regressed}, {"better", d.Improved}, {"severity", d.SeverityChanged},
			{"no longer assessed", d.Unassessed}, {"newly measured", d.Added},
		} {
			if len(row.cs) > 0 {
				p("  %-20s %s\n", row.label, changeList(row.cs))
			}
		}
		switch {
		case d.ScoreFrom != nil && d.ScoreTo != nil:
			p("  %-20s %.1f → %.1f\n", "score", *d.ScoreFrom, *d.ScoreTo)
		case !d.Comparable:
			p("  %-20s judged under a different rubric or check inventory; scores not compared\n", "score")
		}
	}
	writeFramework(w, v.Framework)
	if len(v.Gates) == 0 {
		p("\nthe statement is valid. No gate was asked for, so nothing was judged.\n")
		return
	}
	p("\n")
	for _, g := range v.Gates {
		mark := "✕"
		if g.Met {
			mark = "✓"
		}
		p("%s %-28s %s\n", mark, g.Gate, g.Detail)
	}
	if v.OK {
		p("\nevery gate met.\n")
		return
	}
	p("\nthe statement is valid and a gate was not met.\n")
}

// readInput reads the one positional file, or standard input.
func readInput(args []string) ([]byte, error) {
	if len(args) == 0 || args[0] == "-" {
		return io.ReadAll(os.Stdin)
	}
	b, err := os.ReadFile(args[0]) // #nosec G304 -- the caller named the file
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sortedUnique keeps a repeatable flag's output stable and deduplicated, so
// the same gates asked for twice are reported once.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func init() {
	f := verifyCmd.Flags()
	f.StringVar(&verifyEndpoint, "endpoint", "", "require the statement to be about this target")
	f.StringVar(&verifyTransport, "transport", "http", "transport the --endpoint is reached over: http or stdio")
	f.StringArrayVar(&verifyRequire, "require", nil, "require this check to have passed (repeatable)")
	f.IntVar(&verifyMaxFail, "max-fail", 0, "fail when more than this many checks failed")
	f.Float64Var(&verifyMinScore, "min-score", 0, "fail when the score is below this")
	f.StringVar(&verifyOutput, "output", "text", "output format: text or json")
	f.StringVar(&verifyPolicy, "policy", "", "also judge the statement against this acceptance policy file")
	f.StringVar(&verifyAgainst, "against", "", "an earlier statement about the same target; fail when any check got worse")
	f.AddFlagSet(reproduceFlags())
	f.AddFlagSet(credFlags())
}
