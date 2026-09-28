// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/attest"
)

// attestFixture runs one check against the fake into a report directory and
// returns the endpoint, the JSON report and the attestation.
//
// One run, not two. An earlier version ran check twice — once for each
// format — and the two statements differed in ranAt, took and traceId, which
// is correct: they were different runs. Comparing the two renderings of the
// same run is the contract that matters, and a report directory is where
// both already land.
func attestFixture(t *testing.T) (endpoint, reportJSON, statement string) {
	t.Helper()
	f := newFakeServer(t)
	f.open = true
	endpoint = f.srv.URL + "/mcp"
	dir := t.TempDir()
	out, _ := run(t, append([]string{
		"check", endpoint,
		"--phases", "net,discovery,auth,handshake,catalog",
		"--report-dir", dir,
	}, fastFlags()...)...)

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("the run did not write %s: %v\n%s", name, err, out)
		}
		return string(b)
	}
	return endpoint, read("report.json"), read("attestation.json")
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The saved statement and the one derived from the saved report must be the
// same claim. If they could differ, a pipeline that signs the report in a
// later job would be signing something other than what the run concluded.
func TestAttestFromReportMatchesTheOutputFormat(t *testing.T) {
	endpoint, reportJSON, fromCheck := attestFixture(t)

	path := writeTemp(t, "report.json", reportJSON)
	fromCommand, code := run(t, "attest", path)
	if code != 0 {
		t.Fatalf("passmcp attest exited %d: %s", code, fromCommand)
	}

	a, err := attest.Parse([]byte(fromCheck))
	if err != nil {
		t.Fatalf("the run did not write a valid attestation.json: %v\n%s", err, fromCheck)
	}
	b, err := attest.Parse([]byte(fromCommand))
	if err != nil {
		t.Fatalf("passmcp attest did not produce a valid statement: %v\n%s", err, fromCommand)
	}
	if !a.Covers("http", endpoint) {
		t.Errorf("the statement does not cover the endpoint it was produced from")
	}
	// Byte equality, once both have been through the same marshalling. The
	// two paths build the predicate from the same report, so anything else
	// means one of them added or dropped a field.
	am, _ := a.Marshal()
	bm, _ := b.Marshal()
	if string(am) != string(bm) {
		t.Errorf("the two paths disagree:\nattestation.json:\n%s\npassmcp attest:\n%s", am, bm)
	}
}

// The output format is its own wiring: a reader who never uses a report
// directory asks for the statement on stdout.
func TestCheckOutputAttestation(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	endpoint := f.srv.URL + "/mcp"
	out, _ := run(t, append([]string{
		"check", endpoint, "--output", "attestation", "--phases", "net,discovery,auth,handshake",
	}, fastFlags()...)...)

	st, err := attest.Parse([]byte(out))
	if err != nil {
		t.Fatalf("--output attestation did not produce a valid statement: %v\n%s", err, out)
	}
	if !st.Covers("http", endpoint) {
		t.Errorf("the statement does not cover the endpoint it was produced from: %s", st.Predicate.Target.Endpoint)
	}
}

// Reading from standard input is how this fits a pipeline, and it is the
// default, so it has to work without a filename.
func TestAttestReadsStdin(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
	go func() { _, _ = w.WriteString(reportJSON); _ = w.Close() }()

	out, code := run(t, "attest")
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	if _, err := attest.Parse([]byte(out)); err != nil {
		t.Errorf("stdin path produced an invalid statement: %v\n%s", err, out)
	}
}

// The wrong file is the common mistake — another tool's JSON, or a report
// directory's telemetry — and it has to be named as such rather than
// producing a statement whose subject is an empty string.
func TestAttestRefusesJSONThatIsNotAReport(t *testing.T) {
	path := writeTemp(t, "not-a-report.json", `{"hello":"world"}`)
	out, code := run(t, "attest", path)
	if code == 0 {
		t.Fatalf("a statement was produced from arbitrary JSON:\n%s", out)
	}
}

// Verification is not approval. With no gate asked for, a valid statement is
// a pass and the output has to say that nothing was judged — otherwise a
// pipeline reads exit 0 as "this server is fine".
func TestVerifyWithoutGatesJudgesNothing(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	out, code := run(t, "verify", path)
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	if !strings.Contains(out, "nothing was judged") {
		t.Errorf("the output does not say that no gate was applied:\n%s", out)
	}
}

func TestVerifyEndpointGate(t *testing.T) {
	endpoint, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	t.Run("matching", func(t *testing.T) {
		out, code := run(t, "verify", path, "--endpoint", endpoint)
		if code != 0 {
			t.Fatalf("exited %d: %s", code, out)
		}
		if !strings.Contains(out, "covers") {
			t.Errorf("output:\n%s", out)
		}
	})

	t.Run("different target", func(t *testing.T) {
		out, code := run(t, "verify", path, "--endpoint", "https://other.example.com/mcp")
		if code != 2 {
			t.Fatalf("a statement about another server was accepted (exit %d):\n%s", code, out)
		}
	})

	// A gateway holding a statement for a child process must not accept it
	// for a URL that happens to be spelled the same.
	t.Run("wrong transport", func(t *testing.T) {
		out, code := run(t, "verify", path, "--endpoint", endpoint, "--transport", "stdio")
		if code != 2 {
			t.Fatalf("the transport was ignored (exit %d):\n%s", code, out)
		}
	})
}

func TestVerifyRequireGate(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	t.Run("a check that passed", func(t *testing.T) {
		out, code := run(t, "verify", path, "--require", "net.dns")
		if code != 0 {
			t.Fatalf("exited %d: %s", code, out)
		}
		if !strings.Contains(out, "net.dns passed") {
			t.Errorf("output:\n%s", out)
		}
	})

	// Absent is not a pass. A statement that never ran the check cannot
	// vouch for it, and treating silence as success is how a gate becomes
	// decoration — this run skipped the execution phase entirely.
	t.Run("a check that did not run", func(t *testing.T) {
		out, code := run(t, "verify", path, "--require", "execution.tools_callable")
		if code != 2 {
			t.Fatalf("a check that never ran was treated as passing (exit %d):\n%s", code, out)
		}
		if !strings.Contains(out, "was not run") {
			t.Errorf("the output does not distinguish absent from failed:\n%s", out)
		}
	})

	t.Run("a check that did not pass", func(t *testing.T) {
		// The fake is deliberately open, so this one warns.
		out, code := run(t, "verify", path, "--require", "auth.unauthenticated_tools")
		if code != 2 {
			t.Fatalf("a warning was treated as a pass (exit %d):\n%s", code, out)
		}
	})
}

func TestVerifyCountAndScoreGates(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	st, err := attest.Parse([]byte(statement))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("max-fail", func(t *testing.T) {
		out, code := run(t, "verify", path, "--max-fail", itoa(st.Predicate.Counts.Fail))
		if code != 0 {
			t.Fatalf("exited %d: %s", code, out)
		}
		// One below what this run actually produced, so the gate has to
		// bite. Derived from the statement rather than hard-coded: the count
		// changes as checks are added, and a literal here would make the
		// test pass for the wrong reason.
		want := itoa(st.Predicate.Counts.Fail - 1)
		out, code = run(t, "verify", path, "--max-fail", want)
		if code != 2 {
			t.Fatalf("%d failures passed a max-fail of %s (exit %d):\n%s",
				st.Predicate.Counts.Fail, want, code, out)
		}
	})

	// A gate applies because the flag was given, not because of its value.
	// The strictest useful --max-fail is 0, so a sentinel would have had to
	// sit one below it and a typo would silently turn the gate off.
	t.Run("max-fail 0 is a gate, not a sentinel", func(t *testing.T) {
		if st.Predicate.Counts.Warn == 0 {
			t.Fatal("the fixture has no warnings, so it cannot distinguish a warn from a fail")
		}
		out, code := run(t, "verify", path, "--max-fail", "0")
		// The fake is deliberately open but nothing in these five phases
		// fails outright, so max-fail 0 holds — and the gate must be
		// reported rather than skipped as "not asked for".
		if code != 0 {
			t.Fatalf("exited %d: %s", code, out)
		}
		if !strings.Contains(out, "max-fail") {
			t.Errorf("--max-fail 0 was read as no gate:\n%s", out)
		}
	})

	t.Run("min-score", func(t *testing.T) {
		if st.Predicate.Score == nil {
			// Not a skip: a run over five phases assesses categories, and a
			// statement with no score would mean the predicate dropped it.
			t.Fatal("the statement carries no score, so the gate cannot be exercised")
		}
		out, code := run(t, "verify", path, "--min-score", "0")
		if code != 0 {
			t.Fatalf("exited %d: %s", code, out)
		}
		if !strings.Contains(out, "min-score") {
			t.Errorf("--min-score 0 was read as no gate:\n%s", out)
		}
		out, code = run(t, "verify", path, "--min-score", "101")
		if code != 2 {
			t.Fatalf("a score of %.1f met a minimum of 101 (exit %d):\n%s",
				st.Predicate.Score.Total, code, out)
		}
	})
}

// A statement whose predicate was edited after the digest was taken is
// exactly what an attestation exists to detect, and it must fail as
// unusable — exit 1 — rather than as a gate that was not met.
func TestVerifyRefusesAnEditedStatement(t *testing.T) {
	endpoint, _, statement := attestFixture(t)
	tampered := strings.Replace(statement, endpoint, "https://trustworthy.example.com/mcp", 1)
	if tampered == statement {
		t.Fatal("the endpoint does not appear in the statement, so nothing was tampered with")
	}
	path := writeTemp(t, "tampered.json", tampered)

	out, code := run(t, "verify", path)
	if code != 1 {
		t.Fatalf("an edited statement was not rejected as unusable (exit %d):\n%s", code, out)
	}
}

// The JSON rendering is what a policy engine reads, so it has to carry the
// answer and every gate that produced it.
func TestVerifyJSONOutput(t *testing.T) {
	endpoint, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	out, code := run(t, "verify", path, "--output", "json",
		"--endpoint", endpoint, "--require", "net.dns", "--max-fail", "1000")
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	var v struct {
		OK     bool `json:"ok"`
		Target struct {
			Transport string `json:"transport"`
			Endpoint  string `json:"endpoint"`
		} `json:"target"`
		Gates []struct {
			Gate string `json:"gate"`
			Met  bool   `json:"met"`
		} `json:"gates"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if !v.OK || v.Target.Endpoint != endpoint || v.Target.Transport != "http" {
		t.Errorf("verification = %+v", v)
	}
	if len(v.Gates) != 3 {
		t.Errorf("%d gates reported, want the three that were asked for: %+v", len(v.Gates), v.Gates)
	}
	for _, g := range v.Gates {
		if !g.Met {
			t.Errorf("%s was not met", g.Gate)
		}
	}
}

// Asking for the same gate twice must report it once, or a script counting
// gates gets a different answer for the same policy.
func TestVerifyDeduplicatesRequires(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)

	out, code := run(t, "verify", path, "--output", "json",
		"--require", "net.dns", "--require", "net.dns", "--require", " net.dns ")
	if code != 0 {
		t.Fatalf("exited %d: %s", code, out)
	}
	var v struct {
		Gates []struct{ Gate string } `json:"gates"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Gates) != 1 {
		t.Errorf("%d gates for one repeated check: %+v", len(v.Gates), v.Gates)
	}
}

// itoa without importing strconv into a file that needs nothing else from it.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		return "-" + string(d)
	}
	return string(d)
}

// TestVerifyAgainstAnEarlierStatement. Drift is judged check by check: the
// later statement is the same run with one passing check recorded as a
// failure, so it must be reported as having regressed on exactly that
// check.
func TestVerifyAgainstAnEarlierStatement(t *testing.T) {
	_, _, statement := attestFixture(t)
	earlier := writeTemp(t, "earlier.json", statement)

	st, err := attest.Parse([]byte(statement))
	if err != nil {
		t.Fatal(err)
	}
	var failing string
	for i, v := range st.Predicate.Verdicts {
		if v.Status == "pass" {
			failing = v.ID
			st.Predicate.Verdicts[i].Status, st.Predicate.Verdicts[i].Severity = "fail", "major"
			st.Predicate.Counts.Pass--
			st.Predicate.Counts.Fail++
			break
		}
	}
	if failing == "" {
		t.Fatal("the fixture run passed no check, so there is nothing to regress")
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	later := writeTemp(t, "later.json", string(b))

	t.Run("regressed", func(t *testing.T) {
		out, code := run(t, "verify", later, "--against", earlier)
		if code != 2 {
			t.Fatalf("a regression passed the gate (exit %d):\n%s", code, out)
		}
		if !strings.Contains(out, failing+" pass→fail (major)") || !strings.Contains(out, "worse") {
			t.Errorf("the output does not name the regression:\n%s", out)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		out, code := run(t, "verify", earlier, "--against", earlier)
		if code != 0 || !strings.Contains(out, "no check got worse") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, code := run(t, "verify", later, "--against", earlier, "--output", "json")
		if code != 2 {
			t.Fatalf("exit %d", code)
		}
		var v struct {
			Against struct {
				Regressed []struct{ ID, From, To string } `json:"regressed"`
			} `json:"against"`
		}
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if len(v.Against.Regressed) != 1 || v.Against.Regressed[0].ID != failing {
			t.Errorf("against = %+v", v.Against)
		}
	})

	// Two different servers have no drift between them, only differences,
	// and presenting those as drift is the worse mistake.
	t.Run("another target", func(t *testing.T) {
		other, err := attest.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		other.Predicate.Target.Endpoint = "https://other.example.com/mcp"
		other.Subject = []attest.Subject{attestation.SubjectFor(other.Predicate.Target)}
		ob, _ := other.Marshal()
		out, code := run(t, "verify", later, "--against", writeTemp(t, "other.json", string(ob)))
		if code != 1 || out != "" {
			t.Fatalf("exit %d, stdout:\n%s", code, out)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		if _, code := run(t, "verify", later, "--against", writeTemp(t, "bad.json", "{")); code != 1 {
			t.Errorf("exit %d", code)
		}
		if _, code := run(t, "verify", later, "--against", filepath.Join(t.TempDir(), "absent.json")); code != 1 {
			t.Errorf("exit %d", code)
		}
	})
}
