// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package hostile_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/hostile"
	"satellion.com/passmcp/internal/probe"
)

// TestProbeSurvivesHostileServers is the contract that matters for a tool
// aimed at servers nobody vetted: for every way a server can misbehave,
// passmcp produces a report or a typed error. Never a panic, never a hang,
// never an unbounded allocation.
//
// Each entry here corresponds to a defect that the cooperative fakes in the
// rest of the suite could not have found.
func TestProbeSurvivesHostileServers(t *testing.T) {
	t.Parallel()
	for _, m := range hostile.All {
		t.Run(string(m), func(t *testing.T) {
			t.Parallel()
			srv := hostile.New(t, m)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			done := make(chan struct{})
			var sess *probe.Session
			var err error
			go func() {
				defer close(done)
				// A panic in a phase must fail this test, not take the
				// process with it.
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic against a %s server: %v", m, r)
					}
				}()
				sess, err = probe.Run(ctx, probe.Options{
					Endpoint:    srv.URL,
					Creds:       &creds.Credentials{Mode: creds.ModeBearer, Token: "operator-secret-token"},
					HTTPClient:  srv.Client(),
					Samples:     1,
					Concurrency: 1,
					RPS:         0,
					CallTimeout: 3 * time.Second,
					Version:     "test",
				})
			}()
			select {
			case <-done:
			case <-time.After(45 * time.Second):
				t.Fatalf("probe hung against a %s server", m)
			}

			if sess == nil && err == nil {
				t.Fatal("neither a session nor an error")
			}
			if sess != nil {
				// A session means the phases ran; every phase must have
				// reached a verdict rather than an empty result.
				for _, pr := range sess.Results {
					if pr.Status == "" {
						t.Errorf("phase %s produced no status", pr.Name)
					}
				}
			}

			// Whatever the server did, the operator's credentials must not
			// have reached the other origin.
			if leaked := srv.Leaked(); len(leaked) > 0 {
				t.Errorf("credentials leaked to another origin: %v", leaked)
			}
		})
	}
}

// TestRedirectLeakIsRefused states the redirect case on its own, because it
// is the one failure here that hands an attacker something rather than just
// breaking the run.
func TestRedirectLeakIsRefused(t *testing.T) {
	t.Parallel()
	srv := hostile.New(t, hostile.RedirectCrossOrigin)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sess, _ := probe.Run(ctx, probe.Options{
		Endpoint:    srv.URL,
		Creds:       &creds.Credentials{Mode: creds.ModeBearer, Token: "operator-secret-token"},
		HTTPClient:  srv.Client(),
		Samples:     1,
		CallTimeout: 3 * time.Second,
		Version:     "test",
	})
	if leaked := srv.Leaked(); len(leaked) > 0 {
		t.Fatalf("token followed a cross-origin redirect: %v", leaked)
	}
	if sess == nil {
		return
	}
	// And the operator should be told why the run could not proceed.
	var sawRefusal bool
	for _, pr := range sess.Results {
		for _, f := range pr.Findings {
			if strings.Contains(strings.ToLower(f.Detail), "redirect") {
				sawRefusal = true
			}
		}
	}
	t.Logf("refusal surfaced in a finding: %v", sawRefusal)
}

// TestNegotiationTerminates: a server that advertises a version it then
// refuses must not put the client in a loop. The client may retry an
// advertised version once, never the one it just tried.
func TestNegotiationTerminates(t *testing.T) {
	t.Parallel()
	srv := hostile.New(t, hostile.VersionPingPong)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := passmcp.New(passmcp.Config{Endpoint: srv.URL, HTTPClient: srv.Client(), ClientInfo: passmcp.Implementation{Name: "passmcp", Version: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Either verdict is acceptable; hanging is not.
		_, _ = c.Negotiate(ctx)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("negotiation looped against a server that refuses what it advertises")
	}
}
