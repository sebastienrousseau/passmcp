// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoundTripperInjectsHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get(Header) }))
	defer srv.Close()
	hc := &http.Client{Transport: RoundTripper{Base: srv.Client().Transport}}
	req, _ := http.NewRequestWithContext(WithID(context.Background(), "abc"), "GET", srv.URL, nil)
	if _, err := hc.Do(req); err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Errorf("header = %q", got)
	}
	req, _ = http.NewRequest("GET", srv.URL, nil)
	hc.Do(req)
	if got != "" {
		t.Errorf("header without context id = %q", got)
	}
	if a, b := NewID(), NewID(); a == b || len(a) != 32 {
		t.Errorf("ids %s %s", a, b)
	}
	if FromContext(Ensure(context.Background())) == "" {
		t.Error("Ensure must set an id")
	}
}
