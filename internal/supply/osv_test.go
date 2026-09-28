// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeOSV answers the two endpoints a lookup uses, from tables, and
// records every package URL it was sent, because what leaves the machine
// is the property under test as much as what comes back.
type fakeOSV struct {
	mu      sync.Mutex
	vulns   map[string][]string // purl -> advisory ids
	details map[string]string   // id -> JSON body
	pages   map[string]int      // purl -> extra pages to hand out
	sent    []string
	batchFn func(w http.ResponseWriter, n int) bool // optional override
	vulnErr string                                  // id that answers 500
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		var req struct{ Queries []osvQuery }
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if f.batchFn != nil && f.batchFn(w, len(req.Queries)) {
			return
		}
		type result struct {
			Vulns []map[string]string `json:"vulns,omitempty"`
			Next  string              `json:"next_page_token,omitempty"`
		}
		var resp struct {
			Results []result `json:"results"`
		}
		f.mu.Lock()
		for _, q := range req.Queries {
			f.sent = append(f.sent, q.Package.PURL)
			var res result
			ids := f.vulns[q.Package.PURL]
			if f.pages[q.Package.PURL] > 0 && q.PageToken == "" {
				// First page: one id and a token for the rest.
				res.Vulns = []map[string]string{{"id": ids[0]}}
				res.Next = "page-2"
			} else {
				start := 0
				if q.PageToken != "" {
					start = 1
				}
				for _, id := range ids[start:] {
					res.Vulns = append(res.Vulns, map[string]string{"id": id})
				}
			}
			resp.Results = append(resp.Results, res)
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == f.vulnErr {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		body, ok := f.details[id]
		if !ok {
			body = fmt.Sprintf(`{"id":%q,"summary":"generic"}`, id)
		}
		_, _ = io.WriteString(w, body)
	default:
		http.NotFound(w, r)
	}
}

func startOSV(t *testing.T, f *fakeOSV) string {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv.URL
}

// osvDoc is a document with one of everything a lookup has to decide
// about.
func osvDoc() BOM {
	return BOM{Components: []BOMComponent{
		{Name: "jinja2", PURL: "pkg:pypi/jinja2@2.4.1", BOMRef: "pkg:pypi/jinja2@2.4.1"},
		{Name: "lodash", PURL: "pkg:npm/lodash@4.17.21", BOMRef: "pkg:npm/lodash@4.17.21"},
		{Name: "internal", PURL: "pkg:golang/corp.example.com/billing@v1.0.0", BOMRef: "b", private: true},
		{Name: "unversioned", PURL: "pkg:npm/left-pad", BOMRef: "c"},
		{Name: "jinja2-again", PURL: "pkg:pypi/jinja2@2.4.1", BOMRef: "dup"},
	}}
}

func TestOSVAttachesAdvisoriesToWhatTheyAffect(t *testing.T) {
	f := &fakeOSV{
		vulns: map[string][]string{"pkg:pypi/jinja2@2.4.1": {"GHSA-2", "GHSA-1", "GHSA-1"}},
		details: map[string]string{
			"GHSA-1": `{"id":"GHSA-1","summary":"sandbox escape","aliases":["CVE-2019-10906","CVE-2019-10906"],
				"published":"2019-04-10T14:30:24Z","modified":"2024-09-24T21:03:59Z",
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
				            {"type":"CVSS_V4","score":"CVSS:4.0/AV:N"},{"type":"UNKNOWN","score":"x"}],
				"database_specific":{"severity":"MODERATE"}}`,
		},
	}
	doc := osvDoc()
	if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if len(doc.Vulnerabilities) != 2 || doc.Vulnerabilities[0].ID != "GHSA-1" {
		t.Fatalf("vulnerabilities = %+v, want GHSA-1 and GHSA-2 once each, sorted", doc.Vulnerabilities)
	}
	v := doc.Vulnerabilities[0]
	if len(v.Affects) != 2 || v.Affects[0].Ref != "dup" || v.Affects[1].Ref != "pkg:pypi/jinja2@2.4.1" {
		t.Errorf("affects = %+v, want both components carrying that purl", v.Affects)
	}
	if len(v.References) != 1 || v.References[0].ID != "CVE-2019-10906" {
		t.Errorf("references = %+v", v.References)
	}
	want := []BOMRating{
		{Method: "CVSSv31", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
		{Method: "CVSSv4", Vector: "CVSS:4.0/AV:N"},
		{Severity: "medium", Method: "other"},
	}
	if fmt.Sprint(v.Ratings) != fmt.Sprint(want) {
		t.Errorf("ratings = %+v, want %+v", v.Ratings, want)
	}
	if v.Source == nil || v.Source.URL != "https://osv.dev/vulnerability/GHSA-1" || v.Description != "sandbox escape" {
		t.Errorf("source/description = %+v %q", v.Source, v.Description)
	}
	props := map[string]string{}
	for _, p := range doc.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["passmcp:osv-queried"] != "2" || props["passmcp:osv-advisories"] != "2" || props["passmcp:osv-endpoint"] == "" {
		t.Errorf("metadata = %v", props)
	}
}

// TestOSVNeverSendsWhatDidNotComeFromARegistry. An internal module's
// import path is the kind of name a company keeps to itself, and no
// public database could match it anyway.
func TestOSVNeverSendsWhatDidNotComeFromARegistry(t *testing.T) {
	f := &fakeOSV{}
	doc := osvDoc()
	if got := Queryable(&doc); got != 2 {
		t.Errorf("Queryable = %d, want 2", got)
	}
	if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.sent, ",") != "pkg:npm/lodash@4.17.21,pkg:pypi/jinja2@2.4.1" {
		t.Errorf("sent %v; want the two public, versioned purls, each once", f.sent)
	}
}

func TestOSVFollowsPageTokens(t *testing.T) {
	f := &fakeOSV{
		vulns: map[string][]string{"pkg:npm/lodash@4.17.21": {"A", "B", "C"}},
		pages: map[string]int{"pkg:npm/lodash@4.17.21": 1},
	}
	doc := osvDoc()
	if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 3 {
		t.Errorf("got %d advisories across pages, want 3", len(doc.Vulnerabilities))
	}
}

func TestOSVStopsAnEndlessPaginator(t *testing.T) {
	f := &fakeOSV{batchFn: func(w http.ResponseWriter, n int) bool {
		_, _ = io.WriteString(w, `{"results":[`+strings.Repeat(`{"next_page_token":"again"},`, n-1)+`{"next_page_token":"again"}]}`)
		return true
	}}
	doc := osvDoc()
	err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc)
	if err == nil || !strings.Contains(err.Error(), "paginating") {
		t.Fatalf("err = %v", err)
	}
}

// TestOSVLeavesOutWithdrawnAdvisories: one its own database retracted is
// not a vulnerability.
func TestOSVLeavesOutWithdrawnAdvisories(t *testing.T) {
	f := &fakeOSV{
		vulns:   map[string][]string{"pkg:npm/lodash@4.17.21": {"OLD", "LIVE"}},
		details: map[string]string{"OLD": `{"id":"OLD","withdrawn":"2024-01-01T00:00:00Z"}`},
	}
	doc := osvDoc()
	if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].ID != "LIVE" {
		t.Errorf("vulnerabilities = %+v", doc.Vulnerabilities)
	}
}

// TestOSVFailuresFailTheCall. A document missing its vulnerabilities
// because the lookup broke would read as a clean bill of health.
func TestOSVFailuresFailTheCall(t *testing.T) {
	for name, f := range map[string]*fakeOSV{
		"batch 500": {batchFn: func(w http.ResponseWriter, _ int) bool {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}},
		"short answer": {batchFn: func(w http.ResponseWriter, _ int) bool {
			_, _ = io.WriteString(w, `{"results":[]}`)
			return true
		}},
		"not json": {batchFn: func(w http.ResponseWriter, _ int) bool {
			_, _ = io.WriteString(w, `<html>`)
			return true
		}},
		"detail 500": {vulns: map[string][]string{"pkg:npm/lodash@4.17.21": {"X", "Y"}}, vulnErr: "X"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := osvDoc()
			if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err == nil {
				t.Fatal("a failed lookup was reported as success")
			}
		})
	}
}

func TestOSVRefusesAnOversizedAnswer(t *testing.T) {
	f := &fakeOSV{batchFn: func(w http.ResponseWriter, _ int) bool {
		_, _ = io.WriteString(w, `{"results":[`)
		chunk := strings.Repeat(" ", 1<<20)
		for range osvMaxBody>>20 + 1 {
			_, _ = io.WriteString(w, chunk)
		}
		return true
	}}
	doc := osvDoc()
	err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

func TestOSVEndpointRules(t *testing.T) {
	for _, ok := range []string{"https://api.osv.dev", "http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"} {
		if err := checkOSVEndpoint(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://mirror.corp.example", "ftp://x", "not a url", "https://"} {
		if err := checkOSVEndpoint(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	doc := osvDoc()
	if err := (OSV{Endpoint: "http://mirror.corp.example"}).Annotate(context.Background(), &doc); err == nil {
		t.Error("Annotate used a plain-http remote endpoint")
	}
}

// TestOSVDoesNotFollowARedirectToAnotherHost: the package list would
// arrive somewhere the operator did not name.
func TestOSVDoesNotFollowARedirectToAnotherHost(t *testing.T) {
	elsewhere := &fakeOSV{}
	target := startOSV(t, elsewhere)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(target, "127.0.0.1", "localhost", 1)+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	doc := osvDoc()
	err := (OSV{Endpoint: redirector.URL}).Annotate(context.Background(), &doc)
	if err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("err = %v", err)
	}
	if len(elsewhere.sent) != 0 {
		t.Errorf("the other host received %v", elsewhere.sent)
	}
}

func TestOSVWithNothingToAskSendsNothing(t *testing.T) {
	f := &fakeOSV{batchFn: func(http.ResponseWriter, int) bool {
		t.Error("a request was made with nothing to ask")
		return false
	}}
	doc := BOM{Components: []BOMComponent{{PURL: "pkg:npm/x", BOMRef: "x"}}}
	if err := (OSV{Endpoint: startOSV(t, f)}).Annotate(context.Background(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 0 {
		t.Errorf("vulnerabilities = %+v", doc.Vulnerabilities)
	}
}

func TestOSVHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	doc := osvDoc()
	if err := (OSV{Endpoint: startOSV(t, &fakeOSV{})}).Annotate(ctx, &doc); err == nil {
		t.Fatal("a cancelled lookup succeeded")
	}
}

func TestSeverityAndCVSSMapping(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "critical", "High": "high", "MODERATE": "medium",
		"medium": "medium", "low": "low", "": "", "UNKNOWN": ""} {
		if got := severityWord(in); got != want {
			t.Errorf("severityWord(%q) = %q, want %q", in, got, want)
		}
	}
	for _, tc := range [][3]string{
		{"CVSS_V2", "AV:N", "CVSSv2"}, {"CVSS_V3", "CVSS:3.0/AV:N", "CVSSv3"},
		{"CVSS_V3", "CVSS:3.1/AV:N", "CVSSv31"}, {"CVSS_V4", "CVSS:4.0/AV:N", "CVSSv4"}, {"X", "", ""},
	} {
		if got := cvssMethod(tc[0], tc[1]); got != tc[2] {
			t.Errorf("cvssMethod(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

// TestAdvisoryTextIsBounded: the summary is written by whoever filed it.
func TestAdvisoryTextIsBounded(t *testing.T) {
	d := osvDetail{ID: "X", Summary: strings.Repeat("é", 2*osvSummaryMax)}
	if got := []rune(d.vulnerability().Description); len(got) != osvSummaryMax || got[len(got)-1] != '…' {
		t.Errorf("description is %d runes", len(got))
	}
	if got := truncateText("  short  ", 10); got != "short" {
		t.Errorf("truncateText = %q", got)
	}
}

// TestPrivateMarkingFollowsProvenance: the builders decide what may be
// sent, from where each component came.
func TestPrivateMarkingFollowsProvenance(t *testing.T) {
	doc := sampleBuild().BOM("0.0.3", fixedTime)
	for _, c := range doc.Components {
		want := c.Name == "example.com/vendored" // no checksum: never went through the proxy
		if c.private != want {
			t.Errorf("%s private = %v, want %v", c.Name, c.private, want)
		}
	}
	inv := inspect(t, map[string]string{"package-lock.json": npmV3})
	for _, c := range inv.BOM("0.0.3", fixedTime).Components {
		want := c.Name == "local-thing" || c.Name == "from-git"
		if c.private != want {
			t.Errorf("%s private = %v, want %v", c.Name, c.private, want)
		}
	}
}
