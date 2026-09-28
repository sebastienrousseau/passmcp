// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package ocsf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AC: OCSF-05
func TestEventsAreNotSentInTheClearOrOnARedirect(t *testing.T) {
	for _, bad := range []string{"http://siem.example/ocsf", "ftp://siem.example/ocsf", "not a url", "/relative"} {
		if err := (Sender{Endpoint: bad}).Send(context.Background(), nil); err == nil {
			t.Errorf("sent to %q", bad)
		}
	}
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere++ }))
	defer other.Close()
	named := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer named.Close()
	if err := (Sender{Endpoint: named.URL}).Send(context.Background(), nil); err == nil {
		t.Error("a redirecting endpoint was accepted")
	}
	if elsewhere != 0 {
		t.Errorf("events followed the redirect %d time(s)", elsewhere)
	}
}
