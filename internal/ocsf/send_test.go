// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package ocsf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestTheCallersClientIsNotModified(t *testing.T) {
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere++ }))
	defer other.Close()
	named := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer named.Close()
	// The caller's policy follows every redirect; the sender must refuse
	// them anyway, without writing its own policy into the caller's client.
	var follows int
	follow := func(*http.Request, []*http.Request) error { follows++; return nil }
	cl := &http.Client{CheckRedirect: follow}
	if err := (Sender{Endpoint: named.URL, Client: cl}).Send(context.Background(), nil); err == nil {
		t.Error("a redirecting endpoint was accepted with the caller's client")
	}
	if elsewhere != 0 {
		t.Errorf("events followed the redirect %d time(s)", elsewhere)
	}
	if follows != 0 {
		t.Errorf("the caller's CheckRedirect ran %d time(s) during Send", follows)
	}
	if err := cl.CheckRedirect(nil, nil); err != nil || follows != 1 {
		t.Errorf("the caller's CheckRedirect was replaced: err=%v, calls=%d", err, follows)
	}
}

func TestTheDefaultClientHasATimeout(t *testing.T) {
	for _, c := range []struct {
		set, want time.Duration
	}{{0, 10 * time.Second}, {-time.Second, 10 * time.Second}, {3 * time.Second, 3 * time.Second}} {
		cl := Sender{Timeout: c.set}.httpClient()
		if cl.Timeout != c.want {
			t.Errorf("Timeout %v: client timeout %v, want %v", c.set, cl.Timeout, c.want)
		}
		if err := cl.CheckRedirect(nil, nil); err == nil {
			t.Errorf("Timeout %v: the client follows redirects", c.set)
		}
	}
	caller := &http.Client{Timeout: time.Minute}
	if cl := (Sender{Client: caller, Timeout: time.Second}).httpClient(); cl == caller || cl.Timeout != time.Minute {
		t.Errorf("the caller's client was not copied as it is: same=%v timeout=%v", cl == caller, cl.Timeout)
	}
}
