// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

// TestAnAuthorizationServerThatRebindsIsNeverReached: a server under test
// names an authorization server whose DNS answers a public address when
// the URL policy checks it and a private one when passmcp connects (DNS
// rebinding). The check and the connection must see the same answer, so
// passmcp never connects to the private address.
//
// The fake stands in for the network: every name dials the fake's
// loopback listener, which plays the internal host.
func TestAnAuthorizationServerThatRebindsIsNeverReached(t *testing.T) {
	f := newFakeServer(t)
	const endpoint = "http://mcp.public.test/mcp"
	f.q.prmAS = "http://as.rebind.test/as"
	f.q.prmResource = endpoint

	var mu sync.Mutex
	lookups := 0
	resolver := func(_ context.Context, host string) ([]net.IP, error) {
		if host != "as.rebind.test" {
			return nil, errors.New("no such host")
		}
		mu.Lock()
		defer mu.Unlock()
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil // what the policy's check is told
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil // what any later lookup is told
	}
	listener := f.srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		switch host {
		case "mcp.public.test":
			return d.DialContext(ctx, network, listener)
		case "as.rebind.test":
			// A connection by name resolves again, and gets the second answer.
			if _, err := resolver(ctx, host); err != nil {
				return nil, err
			}
			return d.DialContext(ctx, network, listener)
		}
		return d.DialContext(ctx, network, addr)
	}

	cr := &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "static-id", ClientSecret: "static-secret-value", Sources: map[string]string{"client-id": "flag"}}
	s, err := Run(context.Background(), Options{
		Endpoint: endpoint, Creds: cr, Recorder: telemetry.New(), Dial: dial,
		URLPolicy: auth.URLPolicy{AllowHTTP: true, Resolver: resolver},
		Version:   "test", RPS: -1, Samples: 1,
		// The network phase resolves names itself, outside the transport.
		Skip: []string{"net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	reached := f.hosts["as.rebind.test"]
	f.mu.Unlock()
	if fd := findingsByID(s)["discovery.as"]; fd.Status != Fail || !strings.Contains(fd.Detail, "at connect time") {
		t.Errorf("discovery.as should fail on the connect-time check: %+v", fd)
	}
	if lookups < 2 {
		t.Fatalf("the scenario did not happen: %d lookup(s) of the rebinding name", lookups)
	}
	if reached != 0 {
		t.Fatalf("passmcp sent %d request(s) to the rebinding authorization server's private address", reached)
	}
}
