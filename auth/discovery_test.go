// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPRMCandidates(t *testing.T) {
	got, err := PRMCandidates("https://api.example.com/mcp/v1/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://api.example.com/.well-known/oauth-protected-resource/mcp/v1",
		"https://api.example.com/.well-known/oauth-protected-resource",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestDiscoverPRMFallsBackToWellKnown(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			http.NotFound(w, r)
		case "/.well-known/oauth-protected-resource":
			json.NewEncoder(w).Encode(ProtectedResourceMetadata{Resource: srv0(r) + "/mcp", AuthorizationServers: []string{"https://as.example"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	d := &Discoverer{Client: srv.Client()}
	prm, from, err := d.DiscoverPRM(context.Background(), srv.URL+"/mcp", "")
	if err != nil {
		t.Fatal(err)
	}
	if from != srv.URL+"/.well-known/oauth-protected-resource" {
		t.Errorf("from = %s", from)
	}
	if prm.AuthorizationServers[0] != "https://as.example" {
		t.Errorf("prm = %+v", prm)
	}
	if len(hits) != 2 || hits[0] != "/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("hits = %v", hits)
	}
}

func TestDiscoverPRMHintFirstAndEmptyServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom" {
			json.NewEncoder(w).Encode(ProtectedResourceMetadata{Resource: "x", AuthorizationServers: nil})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	d := &Discoverer{Client: srv.Client()}
	_, _, err := d.DiscoverPRM(context.Background(), srv.URL+"/mcp", srv.URL+"/custom")
	if !errors.Is(err, ErrNoAuthorizationServers) {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscoverServerPathAware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server/tenant1" {
			json.NewEncoder(w).Encode(ServerMetadata{Issuer: "x", TokenEndpoint: "https://x/token"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	d := &Discoverer{Client: srv.Client()}
	md, err := d.DiscoverServer(context.Background(), srv.URL+"/tenant1")
	if err != nil {
		t.Fatal(err)
	}
	if md.TokenEndpoint != "https://x/token" {
		t.Errorf("md = %+v", md)
	}
}

func TestCanonicalResource(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://API.Example.com/":      "https://api.example.com",
		"https://api.example.com/mcp#f": "https://api.example.com/mcp",
		"https://api.example.com/mcp/":  "https://api.example.com/mcp/",
	} {
		got, err := CanonicalResource(in)
		if err != nil || got != want {
			t.Errorf("%s -> %s (%v), want %s", in, got, err, want)
		}
	}
	if _, err := CanonicalResource("/relative"); err == nil {
		t.Error("expected error for relative resource")
	}
}

func srv0(r *http.Request) string { return "http://" + r.Host }
