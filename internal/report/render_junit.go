// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"satellion.com/passmcp/internal/probe"
)

// JUnit renders the report as a JUnit XML suite per phase.
//
// Every CI system on the market reads this format, which is the only
// argument for it: a passmcp run shows up beside the unit tests, in the same
// panel, with the same shape, and nobody has to be told where to look.
//
// The mapping is deliberate rather than convenient:
//
//   - a phase is a testsuite, a check is a testcase
//   - fail becomes <failure>, because a build should go red
//   - warn also becomes <failure>, but typed "warning" — JUnit has no third
//     state, and silently reporting a deviation as a pass is how a warning
//     stops being read
//   - skip becomes <skipped>; info and pass become a passing testcase
//
// The warn decision is the one that will surprise someone. The alternative
// was to drop warnings, and a format that shows only what already failed
// tells a team nothing they did not know.
func JUnit(w io.Writer, r *Report) error {
	if r == nil {
		return nil
	}

	// The totals are summed from the suites rather than taken from
	// r.Counts. They are nearly the same number and drifted apart the
	// moment a phase that never ran got a synthetic skipped case: r.Counts
	// counts findings, and this document counts test cases. A reader that
	// trusts the attribute over the children has no way to notice.
	suites := junitSuites{Name: "passmcp", Time: junitSeconds(r.Duration)}

	for _, ph := range r.Phases {
		suite := junitSuite{
			Name:      "passmcp." + ph.Name,
			Time:      junitSeconds(ph.Duration),
			Timestamp: r.Started.UTC().Format(time.RFC3339),
			Properties: []junitProperty{
				{Name: "endpoint", Value: r.Target.Endpoint},
				{Name: "trace_id", Value: r.TraceID},
				{Name: "phase.title", Value: ph.Title},
			},
		}
		if ph.Summary != "" {
			suite.Properties = append(suite.Properties, junitProperty{Name: "phase.summary", Value: ph.Summary})
		}
		for _, f := range ph.Findings {
			suite.Cases = append(suite.Cases, junitCase(f))
			suite.Tests++
			switch f.Status {
			case probe.Fail, probe.Warn:
				suite.Failures++
			case probe.Skip:
				suite.Skipped++
			}
		}
		if ph.Skipped != "" && len(suite.Cases) == 0 {
			// A phase that never ran still belongs in the report; a suite
			// that simply vanishes reads as a phase that passed.
			suite.Cases = append(suite.Cases, junitTestCase{
				Name:      ph.Name,
				ClassName: "passmcp." + ph.Name,
				Skipped:   &junitSkipped{Message: ph.Skipped},
			})
			suite.Tests++
			suite.Skipped++
		}
		suites.Suites = append(suites.Suites, suite)
		suites.Tests += suite.Tests
		suites.Failures += suite.Failures
		suites.Skipped += suite.Skipped
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// junitCase renders one finding.
func junitCase(f probe.Finding) junitTestCase {
	tc := junitTestCase{
		// The id is the name, not the title: a CI system keys a test's
		// history on this string, and a reworded title would otherwise read
		// as a test that disappeared and a new one that arrived.
		Name:      f.ID,
		ClassName: "passmcp." + f.Phase,
		Time:      junitSeconds(f.Duration),
	}
	body := junitBody(f)
	switch f.Status {
	case probe.Fail:
		sev := string(f.Severity)
		if sev == "" {
			sev = "failure"
		}
		tc.Failure = &junitFailure{Type: sev, Message: junitMessage(f), Text: body}
	case probe.Warn:
		tc.Failure = &junitFailure{Type: "warning", Message: junitMessage(f), Text: body}
	case probe.Skip:
		tc.Skipped = &junitSkipped{Message: junitMessage(f)}
	default:
		if body != "" {
			tc.SystemOut = body
		}
	}
	return tc
}

func junitMessage(f probe.Finding) string {
	if f.Detail != "" {
		return f.Title + ": " + f.Detail
	}
	return f.Title
}

// junitBody is what a person reads when they expand a failed test.
func junitBody(f probe.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", f.Title)
	if f.Detail != "" {
		fmt.Fprintf(&b, "\nObserved: %s\n", f.Detail)
	}
	if f.Advice != "" {
		fmt.Fprintf(&b, "Advice:   %s\n", f.Advice)
	}
	if len(f.Evidence) > 0 {
		fmt.Fprintf(&b, "Evidence: %s\n", strings.Join(f.Evidence, ", "))
	}
	if f.DocURL != "" {
		fmt.Fprintf(&b, "Docs:     %s\n", f.DocURL)
	}
	return b.String()
}

// junitSeconds renders a duration the way JUnit readers expect: seconds,
// as a decimal.
func junitSeconds(m probe.Millis) string {
	return fmt.Sprintf("%.3f", float64(time.Duration(m))/float64(time.Second))
}

// --- the JUnit shape CI systems actually parse -----------------------------
//
// There is no specification; there is the Ant schema everybody copied and a
// pile of readers that accept a superset of it. This writes the common
// subset: testsuites/testsuite/testcase, with failure, skipped and
// system-out.

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Time       string          `xml:"time,attr"`
	Timestamp  string          `xml:"timestamp,attr,omitempty"`
	Properties []junitProperty `xml:"properties>property,omitempty"`
	Cases      []junitTestCase `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr,omitempty"`
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}
