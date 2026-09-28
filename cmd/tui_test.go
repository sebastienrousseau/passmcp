// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/tui"
)

// headless swaps the TTY detection and the Bubble Tea program for ones
// that work under `go test`, restoring them afterwards.
func headless(t *testing.T) {
	t.Helper()
	origTTY, origProg, origSel := stdoutIsTTY, newProgram, runSelector
	stdoutIsTTY = func() bool { return true }
	newProgram = func(m tea.Model) *tea.Program {
		return tea.NewProgram(m, tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutRenderer())
	}
	t.Cleanup(func() { stdoutIsTTY, newProgram, runSelector = origTTY, origProg, origSel })
}

func TestProgressViewPath(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	headless(t)
	out, code := run(t, "check", f.srv.URL+"/mcp", "--rps", "0", "--samples", "1", "--concurrency", "0", "--phases", "net,discovery,handshake,catalog")
	if code != 0 || !strings.Contains(out, "How it scores") || !strings.Contains(out, "Ready") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestInteractiveSelectorPath(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	headless(t)
	var offered []tui.Item
	runSelector = func(ctx context.Context, fetch tui.FetchFunc) ([]tui.Item, bool, error) {
		items, err := fetch()
		if err != nil {
			return nil, false, err
		}
		offered = items
		var chosen []tui.Item
		for _, it := range items {
			if it.Name == "get_time" {
				chosen = append(chosen, it)
			}
		}
		return chosen, true, nil
	}
	out, code := run(t, "check", "-i", f.srv.URL+"/mcp", "--rps", "0", "--samples", "1", "--concurrency", "0", "--phases", "net,discovery,handshake,catalog,execution")
	if code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
	if len(offered) == 0 {
		t.Fatal("selector was not offered the tool list")
	}
	kinds := map[string]string{}
	for _, it := range offered {
		kinds[it.Name] = it.Kind + "/" + it.Policy
	}
	if kinds["get_time"] != "read-only/allowed" || kinds["delete_all"] != "destructive/opt-in" {
		t.Errorf("kinds = %v", kinds)
	}
	if !strings.Contains(out, "How it scores") {
		t.Errorf("selected run should still produce a report:\n%s", out)
	}

	// cancel in the selector: nothing runs, exit 0
	runSelector = func(ctx context.Context, fetch tui.FetchFunc) ([]tui.Item, bool, error) { return nil, false, nil }
	if out, code := run(t, "check", "-i", f.srv.URL+"/mcp"); code != 0 || strings.Contains(out, "Credentials") {
		t.Errorf("cancel: %d %q", code, out)
	}
	// empty selection
	runSelector = func(ctx context.Context, fetch tui.FetchFunc) ([]tui.Item, bool, error) { return nil, true, nil }
	if out, code := run(t, "check", "-i", f.srv.URL+"/mcp"); code != 0 || !strings.Contains(out, "No tools selected") {
		t.Errorf("empty: %d %q", code, out)
	}
	// selector error
	runSelector = func(ctx context.Context, fetch tui.FetchFunc) ([]tui.Item, bool, error) {
		return nil, false, errors.New("tty gone")
	}
	if _, code := run(t, "check", "-i", f.srv.URL+"/mcp"); code != 1 {
		t.Errorf("selector error must exit 1, got %d", code)
	}
}

func TestSelectorItems(t *testing.T) {
	f := newFakeServer(t)
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// The selector now asks the engine, so the case is expressed as the
	// spec every surface builds rather than as this surface's arguments.
	spec := func(endpoint string, cs engine.CredSpec) engine.RunSpec {
		return engine.RunSpec{
			Target: engine.TargetSpec{Endpoint: endpoint},
			Creds:  cs,
		}
	}

	// protected server, bearer token the server knows
	f.mu.Lock()
	f.tokens["tok-valid"] = true
	f.mu.Unlock()
	items, err := selectorItems(context.Background(), spec(f.srv.URL+"/mcp", engine.CredSpec{Mode: "bearer", Token: "tok-valid"}))
	if err != nil || len(items) == 0 {
		t.Fatalf("items %v err %v", items, err)
	}

	// authorization-code without a stored token
	authCode := engine.CredSpec{Mode: "authorization-code"}
	if _, err := selectorItems(context.Background(), spec(f.srv.URL+"/mcp", authCode)); err == nil || !strings.Contains(err.Error(), "passmcp login") {
		t.Errorf("want login hint, got %v", err)
	}

	// authorization-code with a stored token
	st := &creds.Store{}
	f.mu.Lock()
	f.tokens["stored"] = true
	f.mu.Unlock()
	if err := st.Put(creds.StoredToken{Endpoint: f.srv.URL + "/mcp", AccessToken: "stored", TokenURL: f.srv.URL + "/as/token", ClientID: "c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := selectorItems(context.Background(), spec(f.srv.URL+"/mcp", authCode)); err != nil {
		t.Errorf("stored token: %v", err)
	}

	// no credentials against a protected server
	if _, err := selectorItems(context.Background(), spec(f.srv.URL+"/mcp", engine.CredSpec{Mode: "none"})); err == nil {
		t.Error("protected server without credentials must fail")
	}

	// bad endpoint
	if _, err := selectorItems(context.Background(), spec("::", engine.CredSpec{Mode: "none"})); err == nil {
		t.Error("bad endpoint must fail")
	}
	_ = os.Getenv
}
