// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"satellion.com/passmcp"
)

// mixedServer lists one tool of each class, so the classification and the
// policy verdict can be told apart.
func mixedServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "s1")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mixed","version":"1.0"}}}`, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[
				{"name":"read_it","description":"Reads.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}},
				{"name":"write_it","description":"Writes.","annotations":{"readOnlyHint":false,"destructiveHint":false},"inputSchema":{"type":"object"}},
				{"name":"unannotated","description":"Says nothing about itself.","inputSchema":{"type":"object"}}
			]}}`, id)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func choiceByName(cs []ToolChoice, name string) (ToolChoice, bool) {
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return ToolChoice{}, false
}

// TestListToolChoicesClassifiesByAnnotation is what a selector shows, and
// the classification has to follow the specification's defaults rather
// than the server's optimism: a tool that declares nothing is destructive.
func TestListToolChoicesClassifiesByAnnotation(t *testing.T) {
	srv := mixedServer(t)
	spec := RunSpec{Target: TargetSpec{Endpoint: srv.URL}}

	got, err := ListToolChoices(context.Background(), spec, "test")
	if err != nil {
		t.Fatalf("ListToolChoices: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 choices, got %d: %+v", len(got), got)
	}

	read, _ := choiceByName(got, "read_it")
	if read.Kind != "read-only" || read.Policy != "allowed" {
		t.Errorf("read_it = %+v, want read-only/allowed", read)
	}
	if !strings.Contains(read.Description, "Reads") {
		t.Errorf("the server's own text was dropped: %q", read.Description)
	}

	write, _ := choiceByName(got, "write_it")
	if write.Kind != "mutating" || write.Policy != "opt-in" {
		t.Errorf("write_it = %+v, want mutating/opt-in", write)
	}

	// The specification's default for an unannotated tool is destructive,
	// and a selector that showed it as anything else would be inviting a
	// click that the policy exists to make deliberate.
	un, _ := choiceByName(got, "unannotated")
	if un.Kind != "destructive" || un.Policy != "opt-in" {
		t.Errorf("unannotated = %+v, want destructive/opt-in", un)
	}
}

// TestListToolChoicesFollowsTheSpecsPolicy: the same catalogue, listed
// under a widened policy, reports what that policy would now invoke. A
// selector that always said "opt-in" would be lying to a caller who had
// already opted in.
func TestListToolChoicesFollowsTheSpecsPolicy(t *testing.T) {
	srv := mixedServer(t)
	spec := RunSpec{
		Target: TargetSpec{Endpoint: srv.URL},
		Policy: PolicySpec{AllowMutations: true},
	}

	got, err := ListToolChoices(context.Background(), spec, "test")
	if err != nil {
		t.Fatalf("ListToolChoices: %v", err)
	}
	write, _ := choiceByName(got, "write_it")
	if write.Policy != "allowed" {
		t.Errorf("with mutations allowed, write_it should be allowed, got %q", write.Policy)
	}
	un, _ := choiceByName(got, "unannotated")
	if un.Policy != "opt-in" {
		t.Errorf("allowing mutations must not also allow the unannotated: %+v", un)
	}
}

// TestListToolChoicesOverStdio: most MCP servers are programs, so the
// selector has to work over a pipe or it is a selector for the minority.
func TestListToolChoicesOverStdio(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("the fixture server is a shell script")
	}
	dir := t.TempDir()
	path := dir + "/server.sh"
	script := `#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"pipe","version":"1.0"}}}\n' "$id" ;;
    *'"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"piped","description":"From a pipe.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"notifications/'*) : ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}\n' "$id" ;;
  esac
done
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}

	spec := RunSpec{Target: TargetSpec{Command: path}}
	got, err := ListToolChoices(context.Background(), spec, "test")
	if err != nil {
		t.Fatalf("ListToolChoices over stdio: %v", err)
	}
	if len(got) != 1 || got[0].Name != "piped" {
		t.Fatalf("want the piped tool, got %+v", got)
	}
	if got[0].Kind != "read-only" {
		t.Errorf("kind = %q", got[0].Kind)
	}
}

// TestListToolChoicesValidatesBeforeDialing: a spec that a run would
// refuse is refused here too, and for the same reason, so the browser
// cannot reach a target through the selector that it could not reach
// through a run.
func TestListToolChoicesValidatesBeforeDialing(t *testing.T) {
	for name, spec := range map[string]RunSpec{
		"no target":     {},
		"relative":      {Target: TargetSpec{Endpoint: "/mcp"}},
		"not a url":     {Target: TargetSpec{Endpoint: "not a url"}},
		"unknown mode":  {Target: TargetSpec{Endpoint: "https://x/mcp"}, Creds: CredSpec{Mode: "telepathy"}},
		"unknown phase": {Target: TargetSpec{Endpoint: "https://x/mcp"}, Phases: PhaseSpec{Only: []string{"nonsense"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ListToolChoices(context.Background(), spec, "test"); err == nil {
				t.Error("want an error before anything is dialled")
			}
		})
	}
}

// TestListToolChoicesReportsAnUnreachableServer: nothing to select, and
// the reason has to survive to the caller.
func TestListToolChoicesReportsAnUnreachableServer(t *testing.T) {
	spec := RunSpec{Target: TargetSpec{Endpoint: "http://127.0.0.1:1/mcp"}}
	_, err := ListToolChoices(context.Background(), spec, "test")
	if err == nil {
		t.Fatal("want an error from an unreachable server")
	}
}

// TestListToolChoicesNeedsALoginWhenTheTokenIsNotStored is the one error
// that is advice rather than a failure.
func TestListToolChoicesNeedsALoginWhenTheTokenIsNotStored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := mixedServer(t)
	spec := RunSpec{
		Target: TargetSpec{Endpoint: srv.URL},
		Creds:  CredSpec{Mode: "authorization-code"},
	}
	_, err := ListToolChoices(context.Background(), spec, "test")
	if err == nil || !strings.Contains(err.Error(), "passmcp login") {
		t.Fatalf("want a login hint, got %v", err)
	}
}

// TestListToolChoicesOnAServerWithNoTools: an empty catalogue is an empty
// selector, not an error.
func TestListToolChoicesOnAServerWithNoTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"bare","version":"1.0"}}}`, id)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, id)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(srv.Close)

	got, err := ListToolChoices(context.Background(), RunSpec{Target: TargetSpec{Endpoint: srv.URL}}, "test")
	if err != nil {
		t.Fatalf("an empty catalogue is not an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no choices, got %+v", got)
	}
}

// TestListCatalogueReturnsTheWholeTool: a selector wants rows a person
// can read; a watcher wants everything a reviewer approved, schemas and
// annotations included. Both come from the same two requests.
func TestListCatalogueReturnsTheWholeTool(t *testing.T) {
	srv := mixedServer(t)
	got, err := ListCatalogue(context.Background(), RunSpec{Target: TargetSpec{Endpoint: srv.URL}}, "test")
	if err != nil {
		t.Fatalf("ListCatalogue: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 tools, got %d", len(got))
	}

	byName := map[string]passmcp.Tool{}
	for _, tl := range got {
		byName[tl.Name] = tl
	}
	read, ok := byName["read_it"]
	if !ok {
		t.Fatal("read_it is missing")
	}
	// The parts a choice row throws away are exactly what a baseline
	// needs: without the schema and the annotation there is no drift to
	// detect.
	if read.Annotations == nil || read.Annotations.ReadOnlyHint == nil || !*read.Annotations.ReadOnlyHint {
		t.Errorf("the annotation did not survive: %+v", read.Annotations)
	}
	if len(read.InputSchema) == 0 {
		t.Error("the input schema did not survive")
	}
	if read.Description == "" {
		t.Error("the description did not survive")
	}
}

// TestListCatalogueValidatesBeforeDialing, like the selector: a spec a run
// would refuse is refused here too.
func TestListCatalogueValidatesBeforeDialing(t *testing.T) {
	for name, spec := range map[string]RunSpec{
		"no target":    {},
		"relative":     {Target: TargetSpec{Endpoint: "/mcp"}},
		"unknown mode": {Target: TargetSpec{Endpoint: "https://x/mcp"}, Creds: CredSpec{Mode: "telepathy"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ListCatalogue(context.Background(), spec, "test"); err == nil {
				t.Error("want an error before anything is dialled")
			}
		})
	}
}

// TestListCatalogueReportsAnUnreachableServer.
func TestListCatalogueReportsAnUnreachableServer(t *testing.T) {
	_, err := ListCatalogue(context.Background(),
		RunSpec{Target: TargetSpec{Endpoint: "http://127.0.0.1:1/mcp"}}, "test")
	if err == nil {
		t.Fatal("want an error from an unreachable server")
	}
}

// TestListCatalogueNeedsALoginWhenTheTokenIsNotStored, the one error that
// is advice rather than a failure.
func TestListCatalogueNeedsALoginWhenTheTokenIsNotStored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	srv := mixedServer(t)
	_, err := ListCatalogue(context.Background(), RunSpec{
		Target: TargetSpec{Endpoint: srv.URL},
		Creds:  CredSpec{Mode: "authorization-code"},
	}, "test")
	if err == nil || !strings.Contains(err.Error(), "passmcp login") {
		t.Fatalf("want a login hint, got %v", err)
	}
}
