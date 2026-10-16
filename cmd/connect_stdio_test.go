// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/engine"
)

// The fake stdio server is this test binary, re-executed with fakeStdioEnv
// set, the same way internal/probe fakes one: a server in Go, in this file,
// with no build step.
const fakeStdioEnv = "PASSMCP_CMD_FAKE_STDIO"

// TestFakeStdioServer is not a test. Re-executed with fakeStdioEnv set, it
// answers every request on stdin with just enough MCP to connect.
func TestFakeStdioServer(t *testing.T) {
	mode := os.Getenv(fakeStdioEnv)
	if mode == "" {
		t.Skip("helper process for the stdio tests")
	}
	if mode == "exit" {
		os.Exit(2)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(in.Bytes(), &req) != nil || req.ID == nil {
			continue
		}
		result := `{}`
		if req.Method == "initialize" {
			result = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}`
		}
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", req.ID, result)
	}
	// Exit before the testing package prints its verdict onto the pipe.
	os.Exit(0)
}

// fakeStdioTarget runs the fake in mode. extra trails the command line,
// where the test binary ignores it and the recorder still names it.
func fakeStdioTarget(mode string, extra ...string) engine.TargetSpec {
	return engine.TargetSpec{
		Command: os.Args[0],
		Args:    append([]string{"-test.run=^TestFakeStdioServer$"}, extra...),
		Env:     []string{fakeStdioEnv + "=" + mode},
	}
}

// TestConnectWithCredsOverStdio: a stdio target connects, the exchange is
// recorded through RecordPipe, and a credential on the server's command
// line is masked in the first event because the recorder had every secret
// before the first message.
func TestConnectWithCredsOverStdio(t *testing.T) {
	const secret = "tok-stdio-argv-0123456789"
	resetAll()
	token = secret
	cr, err := buildCreds()
	if err != nil {
		t.Fatal(err)
	}
	c, rec, err := connectWithCreds(rootCmd, fakeStdioTarget("serve", secret), cr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	evs := rec.Events()
	if len(evs) == 0 || evs[0].RPC == nil || evs[0].RPC.Method != "initialize" {
		t.Fatalf("the stdio handshake was not recorded first: %+v", evs)
	}
	if !strings.HasPrefix(evs[0].URL, "stdio:") || strings.Contains(evs[0].URL, secret) {
		t.Errorf("first event names the command as %q; want it under stdio: with %q masked", evs[0].URL, secret)
	}
}

func TestConnectWithCredsStdioFailures(t *testing.T) {
	resetAll()
	cr, err := buildCreds()
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]engine.TargetSpec{
		"server exits":    fakeStdioTarget("exit"),
		"no such program": {Command: "/nonexistent/passmcp-fake-server"},
	} {
		if c, _, err := connectWithCreds(rootCmd, target, cr); err == nil {
			_ = c.Close()
			t.Errorf("%s: connected", name)
		}
	}
}
