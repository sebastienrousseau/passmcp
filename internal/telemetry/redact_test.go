// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"strings"
	"testing"
)

// A body masked by key must otherwise be the body the server sent: an id
// above 2^53 keeps its digits and markup is not rewritten as <.
func TestJSONKeepsNumbersAndMarkup(t *testing.T) {
	r := &Redactor{}
	got := r.JSON([]byte(`{"id":9007199254740993,"ratio":1.50,"html":"<a href=\"x\">&</a>","access_token":"tok-fidelity"}`))
	for _, want := range []string{`9007199254740993`, `1.50`, `"<a href=\"x\">&</a>"`, `"access_token":"***"`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON() = %s, want it to contain %s", got, want)
		}
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("JSON() = %q, want no trailing newline", got)
	}
	if strings.Contains(got, "tok-fidelity") {
		t.Errorf("JSON() = %s leaked the token", got)
	}
}

// Input that is not exactly one JSON value still goes through String,
// as it did when the body was parsed with json.Unmarshal.
func TestJSONRejectsTrailingData(t *testing.T) {
	r := &Redactor{}
	r.Add("trailing-secret")
	for _, in := range []string{`{"a":1} {"b":2}`, `{"a":1}x`, `{"a":`} {
		if got, want := r.JSON([]byte(in+"trailing-secret")), r.String(in+"trailing-secret"); got != want {
			t.Errorf("JSON(%q) = %q, want %q", in, got, want)
		}
	}
	if got := r.JSON([]byte(" {\"a\":1}\n ")); got != `{"a":1}` {
		t.Errorf("JSON with surrounding space = %q", got)
	}
}
