// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeSource struct {
	tok   string
	inval atomic.Int32
	scope string
}

func (f *fakeSource) Token(context.Context) (*Token, error) { return &Token{AccessToken: f.tok}, nil }
func (f *fakeSource) Invalidate()                           { f.inval.Add(1); f.tok = "fresh" }
func (f *fakeSource) WithScope(s string) TokenSource {
	return &fakeSource{tok: "scoped:" + s, scope: s}
}

func TestTransportRetriesOnceOn401(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		body, _ := io.ReadAll(r.Body)
		if string(body) != "payload" {
			t.Errorf("body not replayed: %q", body)
		}
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	src := &fakeSource{tok: "stale"}
	hc := &http.Client{Transport: NewTransport(srv.Client().Transport, src)}
	req, _ := http.NewRequest("POST", srv.URL, bytes.NewReader([]byte("payload")))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("payload")), nil }
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || n.Load() != 2 || src.inval.Load() != 1 {
		t.Errorf("status %d calls %d invalidations %d", resp.StatusCode, n.Load(), src.inval.Load())
	}
}

func TestTransportStepsUpOnInsufficientScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scoped:files:write" {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="files:write"`)
			w.WriteHeader(403)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tr := NewTransport(srv.Client().Transport, &fakeSource{tok: "narrow"})
	var stepped string
	tr.StepUp = func(ctx context.Context, required string) (TokenSource, error) {
		stepped = required
		return tr.Source().WithScope(required), nil
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || stepped != "files:write" {
		t.Errorf("status %d stepped %q", resp.StatusCode, stepped)
	}
	// Without a StepUp hook the caller receives a typed error.
	tr2 := NewTransport(srv.Client().Transport, &fakeSource{tok: "narrow"})
	_, err = (&http.Client{Transport: tr2}).Get(srv.URL)
	var ise *InsufficientScopeError
	if err == nil || !errorsAs(err, &ise) || ise.Scope != "files:write" {
		t.Fatalf("err = %v", err)
	}
}

func errorsAs(err error, target **InsufficientScopeError) bool {
	for err != nil {
		var e *InsufficientScopeError
		if errors.As(err, &e) {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
