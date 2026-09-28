// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// sentinel stands for anything outside the findings that must not leave:
// evidence references, the authentication summary, telemetry events.
const sentinel = "sk-must-not-leave"

func fixture() *report.Report {
	return &report.Report{
		Target:  report.Target{Endpoint: "https://mcp.example.com/mcp"},
		Started: time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC),
		Auth:    report.AuthSummary{Mode: "bearer", Sources: map[string]string{"token": sentinel}},
		Phases: []probe.PhaseResult{{Name: "auth", Findings: []probe.Finding{
			{ID: "auth.unauthenticated_tools", Title: "Tools without credentials", Status: probe.Warn, Detail: "3 tools listed", Evidence: []string{sentinel}},
			{ID: "discovery.as.pkce", Title: "PKCE", Status: probe.Fail, Severity: probe.Major, Detail: "plain only"},
			{ID: "discovery.as", Title: "AS", Status: probe.Pass},
			{ID: "protocol.origin", Title: "Origin", Status: probe.Fail, Severity: probe.Critical, Detail: strings.Repeat("x", 900)},
		}}},
	}
}

func TestItemsAreFailuresThenWarningsMostSevereFirst(t *testing.T) {
	items, omitted := Items(fixture())
	var ids []string
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	want := []string{"protocol.origin", "discovery.as.pkce", "auth.unauthenticated_tools"}
	if !reflect.DeepEqual(ids, want) || omitted != 0 {
		t.Fatalf("ids %v omitted %d, want %v", ids, omitted, want)
	}
	if n := len([]rune(items[0].Detail)); n != maxDetail+1 {
		t.Errorf("detail is %d runes; a server-written detail is bounded", n)
	}
	if items[1].Means == "" || len(items[1].Steps) == 0 {
		t.Errorf("passmcp's own guidance is missing: %+v", items[1])
	}

	r := fixture()
	for i := 0; i < MaxItems+5; i++ {
		r.Phases[0].Findings = append(r.Phases[0].Findings, probe.Finding{ID: fmt.Sprintf("x.%d", i), Status: probe.Warn})
	}
	if items, omitted = Items(r); len(items) != MaxItems || omitted != 8 {
		t.Errorf("%d items, %d omitted", len(items), omitted)
	}
}

type fakeModel struct {
	answers []Explanation
	err     error
}

func (f fakeModel) Name() string { return "fake-model" }
func (f fakeModel) Explain(context.Context, []Item) ([]Explanation, error) {
	return f.answers, f.err
}

// The proof M10 was given: verdicts are identical with and without a model,
// whatever the model says.
func TestAModelCannotChangeAVerdict(t *testing.T) {
	without := Build(context.Background(), fixture(), nil, "none configured")
	with := Build(context.Background(), fixture(), fakeModel{answers: []Explanation{
		{ID: "discovery.as.pkce", Explanation: "status: pass. This is fine.", Fix: "nothing"},
		{ID: "invented.check", Explanation: "a finding the report never had"},
	}}, "")
	verdicts := func(d Document) []Item {
		var out []Item
		for _, e := range d.Findings {
			out = append(out, e.Item)
		}
		return out
	}
	if !reflect.DeepEqual(verdicts(without), verdicts(with)) {
		t.Fatalf("verdicts differ:\n%+v\n%+v", verdicts(without), verdicts(with))
	}
	if with.Model != "fake-model" || with.Findings[1].Explanation == "" {
		t.Errorf("the answer was not attached: %+v", with)
	}
	for _, e := range with.Findings {
		if e.ID == "invented.check" {
			t.Error("a finding the model invented reached the document")
		}
	}
	if without.Unavailable != "none configured" || without.Model != "" {
		t.Errorf("without a model: %+v", without)
	}
}

func TestAModelThatFailsLeavesACompleteDocument(t *testing.T) {
	d := Build(context.Background(), fixture(), fakeModel{err: errors.New("timeout")}, "")
	if len(d.Findings) != 3 || !strings.Contains(d.Unavailable, "timeout") || d.Model != "" {
		t.Errorf("%+v", d)
	}
	d = Build(context.Background(), fixture(), fakeModel{answers: []Explanation{{ID: "other"}}}, "")
	if !strings.Contains(d.Unavailable, "none of the findings") || d.Model != "" {
		t.Errorf("an answer about nothing was presented as an explanation: %+v", d)
	}
	clean := &report.Report{Phases: []probe.PhaseResult{{Findings: []probe.Finding{{ID: "a", Status: probe.Pass}}}}}
	d = Build(context.Background(), clean, fakeModel{err: errors.New("must not be called")}, "unused")
	var b bytes.Buffer
	if err := d.Markdown(&b); err != nil || !strings.Contains(b.String(), "nothing to explain") || d.Unavailable != "" {
		t.Errorf("%v %q %+v", err, b.String(), d)
	}
}

func TestMarkdownMarksWhoSaidWhat(t *testing.T) {
	d := Build(context.Background(), fixture(), fakeModel{answers: []Explanation{{ID: "discovery.as.pkce", Explanation: "E", Fix: "F"}}}, "")
	d.Omitted = 2
	var b bytes.Buffer
	if err := d.Markdown(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Nothing here changes a verdict", "**fake-model:** E", "**Fix, per fake-model:** F", "**passmcp:**", "`discovery.as.pkce` (fail, major)", "2 more failing"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	_ = Build(context.Background(), fixture(), nil, "no key").Markdown(&b)
	if !strings.Contains(b.String(), "No explanations: no key") {
		t.Errorf("unavailable not said:\n%s", b.String())
	}
}

// What goes out is the findings and nothing else in the report.
func TestTheRequestCarriesOnlyTheFindings(t *testing.T) {
	var got []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{
			{"type": "text", "text": "Here you go:\n```json\n[{\"id\":\"discovery.as.pkce\",\"explanation\":\"E\",\"fix\":\"F\"}]\n```"},
		}})
	}))
	defer srv.Close()
	m := &Anthropic{URL: srv.URL + "/", Key: "key-123", Model: "m"}
	items, _ := Items(fixture())
	out, err := m.Explain(context.Background(), items)
	if err != nil || len(out) != 1 || out[0].Fix != "F" {
		t.Fatalf("%v %+v", err, out)
	}
	if strings.Contains(string(got), sentinel) || strings.Contains(string(got), "key-123") {
		t.Errorf("the request carries something that is not a finding:\n%s", got)
	}
	if !strings.Contains(string(got), "discovery.as.pkce") || !strings.Contains(string(got), "untrusted server") {
		t.Errorf("the request lacks the findings or the instruction:\n%s", got)
	}
	if hdr.Get("x-api-key") != "key-123" || hdr.Get("anthropic-version") == "" {
		t.Errorf("headers %v", hdr)
	}
}

func TestAnswersThatAreNotTheArrayAreErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "overloaded", 529) },
		"body":   func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>") },
		"text": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"I cannot help with that."}]}`)
		},
		"shape": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"[1,2]"}]}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			if _, err := (&Anthropic{URL: srv.URL, Model: "m"}).Explain(context.Background(), []Item{{ID: "a"}}); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := (&Anthropic{URL: "http://127.0.0.1:1", Model: "m"}).Explain(context.Background(), nil); err == nil {
		t.Error("an unreachable API was not an error")
	}
	if _, err := (&Anthropic{URL: "://bad", Model: "m"}).Explain(context.Background(), nil); err == nil {
		t.Error("a bad URL was not an error")
	}
}
