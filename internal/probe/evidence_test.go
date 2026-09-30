// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/telemetry"
)

// testOnlyPrefix marks the check ids this file invents to provoke the rule;
// the suite-wide guard in TestMain ignores them.
const testOnlyPrefix = "test.evidence."

func evidenceSession(t *testing.T) *Session {
	t.Helper()
	return &Session{Opts: Options{Recorder: telemetry.New()}}
}

// TestAPassWithoutEvidenceIsRecordedAsInfo is ADR-0002 enforced: before,
// the rule was a convention, and a check that returned pass without making
// a request or citing anything was recorded as a pass.
func TestAPassWithoutEvidenceIsRecordedAsInfo(t *testing.T) {
	s := evidenceSession(t)
	f := s.check(testOnlyPrefix+"none", "Nothing was asked").pass("looks fine")
	if f.Status != Info || !strings.Contains(f.Detail, "ADR-0002") {
		t.Fatalf("an unevidenced pass was recorded as %s: %q", f.Status, f.Detail)
	}

	// A pass that cites an observation of its own stands.
	f = s.check(testOnlyPrefix+"observed", "Something was seen").ev("addr=192.0.2.1").pass("resolved")
	if f.Status != Pass {
		t.Errorf("a pass with its own evidence became %s", f.Status)
	}

	// So does one whose window contains a recorded request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := s.check(testOnlyPrefix+"requested", "A request was made")
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := (&http.Client{Transport: s.Opts.Recorder.Wrap(nil)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if f := c.pass("answered"); f.Status != Pass || len(f.Evidence) != 1 || !strings.HasPrefix(f.Evidence[0], "req#") {
		t.Errorf("a pass that made a request = %+v", f)
	}

	// A derived check passes on the evidence of the finding it names.
	if f := s.check("catalog.tools.unique", "Tool names are unique").pass("3 tools, no duplicates"); f.Status != Pass {
		t.Errorf("a derived check became %s", f.Status)
	}
	// Other verdicts are not the rule's business.
	if f := s.check(testOnlyPrefix+"warn", "w").warn("odd", "fix it"); f.Status != Warn {
		t.Errorf("a warn became %s", f.Status)
	}
}

// TestDerivedChecksAreRealChecks keeps the list of exceptions honest: an
// entry for a check that does not exist, or no longer exists, is an
// exception nobody is using and should be deleted rather than kept.
func TestDerivedChecksAreRealChecks(t *testing.T) {
	b, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for id, basis := range derivedChecks {
		if basis == "" {
			t.Errorf("%s names no basis", id)
		}
		if !strings.Contains(doc, "`"+id) {
			t.Errorf("%s is listed as a derived check but is not in the inventory", id)
		}
	}
	if _, ok := derivedBasis("catalog.text.hidden"); !ok {
		t.Error("a family prefix does not match its members")
	}
	if _, ok := derivedBasis("catalog.textual"); ok {
		t.Error("a family prefix matched an id outside the family")
	}
}
