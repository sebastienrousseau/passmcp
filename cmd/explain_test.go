// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestExplainWithoutAModelSendsNothing(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	path := writeTemp(t, "report.json", reportJSON)
	// A key in the environment is not a request to send.
	t.Setenv("ANTHROPIC_API_KEY", "k")
	out, stderr, code := runCapturingStderr(t, "explain", path, "--api-url", "http://127.0.0.1:1")
	if code != 0 || !strings.Contains(out, "No explanations: no model was asked for") || !strings.Contains(out, "**passmcp:**") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(stderr, "sending") {
		t.Errorf("announced a send that did not happen: %s", stderr)
	}
}

func TestExplainAnnotatesAndLeavesTheReportAlone(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	path := writeTemp(t, "report.json", reportJSON)
	var asked int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		// Answer about every id asked, with a claim that tries to re-grade.
		var items []struct{ ID string }
		c := req.Messages[0].Content
		_ = json.Unmarshal([]byte(c[strings.IndexByte(c, '['):]), &items)
		var answers []map[string]string
		for _, it := range items {
			answers = append(answers, map[string]string{"id": it.ID, "explanation": "this is actually a pass", "fix": "none"})
		}
		text, _ := json.Marshal(answers)
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": string(text)}}})
	}))
	defer srv.Close()
	t.Setenv("PASSMCP_TEST_MODEL_KEY", "k")

	out, stderr, code := runCapturingStderr(t, "explain", path, "--api-key-env", "PASSMCP_TEST_MODEL_KEY", "--api-url", srv.URL, "--output", "json", "--model", "test-model")
	if code != 0 || asked != 1 {
		t.Fatalf("exit %d, asked %d:\n%s", code, asked, out)
	}
	if !strings.Contains(stderr, "sending") || !strings.Contains(stderr, srv.URL) {
		t.Errorf("the destination was not announced: %q", stderr)
	}
	var doc struct {
		Model    string
		Findings []struct{ ID, Status, Explanation string }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Model != "test-model" || len(doc.Findings) == 0 {
		t.Fatalf("%+v", doc)
	}
	for _, f := range doc.Findings {
		if f.Status == "pass" || f.Explanation == "" {
			t.Errorf("%+v", f)
		}
	}
	after, _ := os.ReadFile(path)
	if string(after) != reportJSON {
		t.Error("the report file changed")
	}
}

func TestExplainRefusesWhatItCannotUse(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	_, reportJSON, _ := attestFixture(t)
	path := writeTemp(t, "report.json", reportJSON)
	for _, args := range [][]string{
		{"explain", path, "--model", "m", "--api-url", "http://api.example.com"},
		{"explain", path, "--model", "m", "--api-url", "::"},
		{"explain", path, "--model", "m", "--api-key-env", "PASSMCP_TEST_UNSET_KEY"},
		{"explain", path, "--output", "html"},
		{"explain", writeTemp(t, "bad.json", "{")},
		{"explain", writeTemp(t, "empty.json", "{}")},
		{"explain", "/does/not/exist.json"},
	} {
		if out, code := run(t, args...); code != 1 || out != "" {
			t.Errorf("%v: exit %d, stdout %q", args[2:], code, out)
		}
	}
}

func TestExplainURLAllowsTLSAndLoopbackOnly(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://api.anthropic.com": true,
		"http://127.0.0.1:8080":     true,
		"http://localhost:8080":     true,
		"http://[::1]:8080":         true,
		"http://10.0.0.1":           false,
		"ftp://x.example":           false,
	} {
		if err := explainURLAllowed(raw); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
