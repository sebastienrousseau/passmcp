// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/supply"
)

// resetAll restores every package-level flag variable and command state.
func resetAll() {
	resetFlags()
	allowMutations, allowDestructive = false, false
	onlyTools, denyTools = nil, nil
	samples, concurrency, rps, callTimeout, seed = 5, 4, 2, 30*time.Second, 1
	fillOpt, allowLoad, maxRes, maxPrompts = false, false, 25, 25
	output, reportDir, captureBodies, withEvents, verbose, noColor = "text", "", false, false, false, false
	interactive = false
	phasesOnly, phasesSkip = nil, nil
	callArgsJSON, callArgs, promptArgs = "", nil, nil
	redirectPort, tokenAuthMethod = 8976, ""
	userAgent = ""
	logLevel = "info"
	verifyEndpoint, verifyTransport, verifyRequire = "", "http", nil
	verifyAgainst = ""
	verifyReproduce, reproPerm = false, reproducePermissions{}
	overlapOutput = "text"
	explainModel, explainKeyEnv, explainURL, explainOutput = "", "ANTHROPIC_API_KEY", "https://api.anthropic.com", "md"
	verifyMaxFail, verifyMinScore, verifyOutput = 0, 0.0, "text"
	verifyPolicy, policyFile = "", ""
	baselineFile, approveBaseline = "", false
	badgeLabel = "passmcp"
	sbomOSV, sbomOSVURL = false, supply.DefaultOSVEndpoint
	watchInterval, watchOnce = 0, false
	watchEgress, expectEgress, plantCanaries, faultUpstream = false, nil, false, false
	retain, verifyFramework = "", ""
	evidenceFramework, evidenceFrom, evidenceTo, evidenceOutDir, evidenceReports = "", "", "", ".", nil

	wrongAudienceTokenEnv, clientConfigFile = "", ""

	ocsfEndpoint, ocsfHeaders = "", nil
	fleetState, fleetOutput, fleetOCSFEndpoint, fleetOCSFHeaders = "", "text", "", nil

	a2aOutput, a2aTimeout, a2aAllowPrivate = "text", 20*time.Second, false
	// cobra remembers Changed between runs, and the help flag keeps its
	// value, so a --help run would turn every later run into help output.
	reset := func(f *pflagFlag) {
		f.Changed = false
		if f.Name == "help" {
			_ = f.Value.Set("false")
		}
	}
	for _, c := range append(rootCmd.Commands(), rootCmd) {
		c.Flags().VisitAll(reset)
		c.PersistentFlags().VisitAll(reset)
		for _, sub := range c.Commands() {
			sub.Flags().VisitAll(reset)
		}
	}
}

// run executes the CLI with args, capturing stdout and the exit code passed
// to osExit (0 when it was never called).
func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	out, _, code := runCapturingStderr(t, args...)
	return out, code
}

// runCapturingStderr is run, plus the diagnostic stream. Kept separate
// because almost every caller only wants the report, and threading a third
// return value through all of them would obscure what they assert.
func runCapturingStderr(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	resetAll()
	origExit := osExit
	code := 0
	osExit = func(c int) { code = c }
	defer func() { osExit = origExit }()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = io.Copy(&buf, r) }()
	var stderr bytes.Buffer
	diag.SetOutput(&stderr)
	rootCmd.SetArgs(args)
	rootCmd.SetOut(w)
	rootCmd.SetErr(io.Discard)
	ExecuteContext(context.Background())
	_ = w.Close()
	wg.Wait()
	os.Stdout = origStdout
	diag.SetOutput(nil)
	return buf.String(), stderr.String(), code
}

func fastFlags() []string {
	return []string{"--rps", "0", "--samples", "1", "--concurrency", "2", "--log-level", "error"}
}

func TestCheckTextAgainstProtectedServer(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	out, code := run(t, append([]string{"check", f.srv.URL + "/mcp", "--auth", "client-credentials", "--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1", "-v"}, fastFlags()...)...)
	if code != 2 {
		t.Fatalf("expected exit 2 (search violates its outputSchema), got %d\n%s", code, out)
	}
	for _, want := range []string{"Not ready for agents", "What to improve", "How it scores", "Checks in detail", "Credentials", "search", "req#"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "sec") && strings.Contains(out, "client_secret=sec") {
		t.Error("secret leaked into the text report")
	}
	if f.calls["delete_all"] != 0 {
		t.Fatal("destructive tool invoked")
	}
}

func TestCheckJSONMdNdjsonAndReportDir(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	dir := t.TempDir()

	out, _ := run(t, append([]string{"check", f.srv.URL + "/mcp", "--output", "json", "--events", "--report-dir", dir, "--capture-bodies", "--phases", "net,discovery,auth,handshake,catalog,execution"}, fastFlags()...)...)
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json output: %v\n%s", err, out)
	}
	if rep["events"] == nil || len(rep["events"].([]any)) == 0 {
		t.Error("--events should embed telemetry")
	}
	// A report directory is what one person hands another, so what it
	// contains is part of the contract rather than an implementation
	// detail. Asserting the set, not the count: a bare number went stale
	// the moment a format was added and said nothing about which.
	wantFiles := []string{
		"report.json", "report.md", "report.html", "report.txt",
		"report.sarif", "report.junit.xml", "report.ocsf.json",
		// Not a report: the in-toto claim, which is the only file in the
		// directory a machine can act on without reading prose.
		"attestation.json",
		"telemetry.ndjson", "telemetry.har",
	}
	for _, name := range wantFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s", name)
		}
	}
	har, err := os.ReadFile(filepath.Join(dir, "telemetry.har"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []any `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(har, &doc); err != nil || len(doc.Log.Entries) == 0 {
		t.Errorf("har invalid: %v", err)
	}
	files, _ := rep["files"].([]any)
	got := make([]string, 0, len(files))
	for _, f := range files {
		s, _ := f.(string)
		got = append(got, filepath.Base(s))
	}
	sort.Strings(got)
	want := slices.Clone(wantFiles)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("report.files = %v, want %v", got, want)
	}

	out, _ = run(t, append([]string{"check", f.srv.URL + "/mcp", "--output", "md", "--phases", "net,handshake"}, fastFlags()...)...)
	if !strings.HasPrefix(out, "# MCP diagnostic:") || !strings.Contains(out, "## Step by step") {
		t.Errorf("md output:\n%s", out)
	}

	out, _ = run(t, append([]string{"check", f.srv.URL + "/mcp", "--output", "ndjson", "--phases", "net,handshake"}, fastFlags()...)...)
	types := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var ev struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("ndjson line: %v: %s", err, line)
		}
		types[ev.Type]++
	}
	if types["phase"] != 2 || types["report"] != 1 || types["request"] == 0 || types["finding"] == 0 {
		t.Errorf("ndjson types = %v", types)
	}

	out, code := run(t, append([]string{"check", f.srv.URL + "/mcp", "--output", "json", "--skip-phases", "performance,resilience,execution,protocol,catalog"}, fastFlags()...)...)
	if code != 0 {
		t.Errorf("open server subset should be clean, exit %d", code)
	}
	rep = nil
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep["events"] != nil {
		t.Errorf("events must be omitted without --events: %v", err)
	}
}

func TestConnectToolsAndCall(t *testing.T) {
	f := newFakeServer(t)
	out, code := run(t, append([]string{"connect", f.srv.URL + "/mcp", "--token", "anything"}, fastFlags()...)...)
	if code != 2 || (!strings.Contains(out, "Couldn't finish") && !strings.Contains(out, "rejected at initialize")) {
		t.Errorf("bad bearer should fail: code %d\n%s", code, out)
	}
	f.open = true
	out, code = run(t, append([]string{"tools", f.srv.URL + "/mcp", "--output", "json"}, fastFlags()...)...)
	if code != 0 {
		t.Errorf("tools exit %d\n%s", code, out)
	}
	var rep struct {
		Catalog struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"catalog"`
		Phases []struct{ Name string } `json:"phases"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Catalog.Tools) != 3 || len(rep.Phases) != 5 {
		t.Errorf("tools output: %v tools=%d phases=%d", err, len(rep.Catalog.Tools), len(rep.Phases))
	}

	out, code = run(t, "call", f.srv.URL+"/mcp", "search", "--arg", "q=hello", "--log-level", "error")
	if code != 0 || !strings.Contains(out, "search ok in") || !strings.Contains(out, "image content") || !strings.Contains(out, "structuredContent") {
		t.Errorf("call text: code %d\n%s", code, out)
	}
	out, code = run(t, "call", f.srv.URL+"/mcp", "search", "--json", `{"q":"x"}`, "--output", "json", "--log-level", "error")
	var res map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res["tool"] != "search" || res["duration_ms"] == nil {
		t.Errorf("call json: code %d\n%s", code, out)
	}
	out, code = run(t, "call", f.srv.URL+"/mcp", "search", "--json", "{}", "--log-level", "error")
	if code != 0 || !strings.Contains(out, "isError") {
		t.Errorf("call isError: code %d\n%s", code, out)
	}
	_, code = run(t, "call", f.srv.URL+"/mcp", "search", "--arg", "noequals")
	if code != 1 {
		t.Error("bad --arg must exit 1")
	}
	_, code = run(t, "call", f.srv.URL+"/mcp", "search", "--json", "{broken")
	if code != 1 {
		t.Error("bad --json must exit 1")
	}
	_, code = run(t, "call", f.srv.URL+"/mcp", "search", "--auth", "bearer")
	if code != 1 {
		t.Error("bearer without token must exit 1")
	}
}

func TestCheckErrorPaths(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	if _, code := run(t, "check", f.srv.URL+"/mcp", "--output", "xml"); code != 1 {
		t.Error("bad --output")
	}
	if _, code := run(t, "check", f.srv.URL+"/mcp", "--arg", "bad"); code != 1 {
		t.Error("bad --arg")
	}
	if _, code := run(t, "check"); code != 1 {
		t.Error("missing endpoint")
	}
	if _, code := run(t, "check", "not a url", "--log-level", "error"); code != 1 {
		t.Error("bad endpoint")
	}
	if _, code := run(t, "check", f.srv.URL+"/mcp", "--log-level", "loud"); code != 1 {
		t.Error("bad log level")
	}
	if _, code := run(t, "check", f.srv.URL+"/mcp", "--auth", "bearer"); code != 1 {
		t.Error("bearer without token")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	_ = os.WriteFile(p, []byte(`{"profiles":{"p":{"endpoint":"x"}}}`), 0o600)
	if _, code := run(t, "check", "--config", p, "--profile", "nope"); code != 1 {
		t.Error("missing profile")
	}
	if _, code := run(t, "check", f.srv.URL+"/mcp", "--config", filepath.Join(dir, "missing.json")); code != 1 {
		t.Error("explicit missing config must fail")
	}
	// A report directory that cannot be created. The path is a child of a
	// regular file, which no platform will turn into a directory — /dev/null
	// used to stand in for this, and on Windows that is just a relative name
	// the runner happily creates.
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, append([]string{"check", f.srv.URL + "/mcp", "--phases", "net", "--report-dir", filepath.Join(blocker, "impossible")}, fastFlags()...)...); code != 1 {
		t.Error("unwritable report dir")
	}
}

func TestProfileDrivesCheck(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	_ = os.WriteFile(p, []byte(`{"defaults":{"rps":0,"samples":1,"log-level":"error"},"profiles":{"fake":{"endpoint":"`+f.srv.URL+`/mcp","settings":{"phases":["net","handshake"],"output":"json","concurrency":0}}}}`), 0o600)
	out, code := run(t, "check", "--config", p, "--profile", "fake")
	var rep struct {
		Phases []struct{ Name string } `json:"phases"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Phases) != 2 {
		t.Errorf("profile run: code %d phases %d\n%s", code, len(rep.Phases), out)
	}
	t.Setenv("PASSMCP_LOG_LEVEL", "debug")
	if _, code := run(t, "check", "--config", p, "--profile", "fake"); code != 0 {
		t.Error("env log level")
	}
}

// lockedBuffer is a bytes.Buffer safe for a writer goroutine and a reader.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitListener blocks until something accepts TCP on addr, without sending
// a request that would consume the login callback.
func waitListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("redirect listener never came up on %s", addr)
}

// loginWithRedirect runs `passmcp login` in the background and delivers the
// given callback query once the loopback listener is up. It returns the
// exit code and everything the CLI wrote to stderr.
func loginWithRedirect(t *testing.T, endpoint, port string, query func(stderr string) string) (int, string) {
	t.Helper()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = stderrW
	errBuf := &lockedBuffer{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = io.Copy(errBuf, stderrR) }()

	var code int
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, code = run(t, "login", endpoint, "--redirect-port", port, "--log-level", "error")
	}()
	// Whatever happens below, the CLI goroutine must finish before the next
	// test touches the package-level flag variables.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("login command did not finish")
		}
	})
	waitListener(t, "127.0.0.1:"+port)
	deadline := time.Now().Add(5 * time.Second)
	q := ""
	for time.Now().Before(deadline) && q == "" {
		q = query(errBuf.String())
		if q == "" {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if q == "" {
		os.Stderr = origStderr
		t.Fatalf("no authorize URL seen on stderr: %q", errBuf.String())
	}
	resp, err := http.Get("http://127.0.0.1:" + port + "/callback?" + q)
	if err != nil {
		os.Stderr = origStderr
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	<-done
	_ = stderrW.Close()
	wg.Wait()
	os.Stderr = origStderr
	return code, errBuf.String()
}

func stateFrom(stderr string) string {
	i := strings.Index(stderr, "state=")
	if i < 0 {
		return ""
	}
	state := stderr[i+len("state="):]
	if j := strings.IndexAny(state, "&\n "); j >= 0 {
		state = state[:j]
	}
	return state
}

func TestLoginErrorRedirect(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	code, stderr := loginWithRedirect(t, f.srv.URL+"/mcp", "18976", func(s string) string {
		if stateFrom(s) == "" {
			return ""
		}
		return "error=access_denied&error_description=user+said+no"
	})
	if code != 1 || !strings.Contains(stderr, "access_denied") {
		t.Errorf("login with an error redirect should exit 1, got %d\n%s", code, stderr)
	}
}

func TestLoginWrongState(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	code, stderr := loginWithRedirect(t, f.srv.URL+"/mcp", "18978", func(s string) string {
		if stateFrom(s) == "" {
			return ""
		}
		return "code=the-code&state=forged"
	})
	if code != 1 || !strings.Contains(stderr, "state mismatch") {
		t.Errorf("forged state should be refused, got %d\n%s", code, stderr)
	}
}

func TestLoginHappyPath(t *testing.T) {
	f := newFakeServer(t)
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	code, stderr := loginWithRedirect(t, f.srv.URL+"/mcp", "18977", func(s string) string {
		if st := stateFrom(s); st != "" {
			return "code=the-code&state=" + st
		}
		return ""
	})
	if code != 0 {
		t.Fatalf("login exit %d\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "token stored in") {
		t.Errorf("stderr lacks confirmation: %s", stderr)
	}
	storePath := filepath.Join(xdg, "passmcp", "tokens.json")
	st, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("token store not written: %v", err)
	}
	// Windows reports a mode Go synthesises from the DOS attributes, so
	// there is no 0600 to assert; see internal/creds/perm_windows.go.
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("store mode = %o", st.Mode().Perm())
	}
	b, _ := os.ReadFile(storePath)
	if !strings.Contains(string(b), "rt-issued-token") || !strings.Contains(string(b), f.srv.URL+"/mcp") {
		t.Errorf("store content: %s", b)
	}
	// The stored token now drives a check and a call.
	if _, code := run(t, append([]string{"check", f.srv.URL + "/mcp", "--auth", "authorization-code", "--phases", "net,discovery,auth,handshake", "--output", "json"}, fastFlags()...)...); code != 0 {
		t.Errorf("check with stored token exit %d", code)
	}
	if out, code := run(t, "call", f.srv.URL+"/mcp", "get_time", "--auth", "authorization-code", "--log-level", "error"); code != 0 || !strings.Contains(out, "now") {
		t.Errorf("call with stored token: %d %s", code, out)
	}
	// An open server needs no login.
	f.open = true
	if _, code := run(t, "login", f.srv.URL+"/mcp", "--log-level", "error"); code != 0 {
		t.Error("login against open server should be a no-op")
	}
}

func TestAuthorizationCodeWithoutStore(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, code := run(t, "call", f.srv.URL+"/mcp", "get_time", "--auth", "authorization-code", "--log-level", "error"); code != 1 {
		t.Error("call without stored token must fail")
	}
	out, code := run(t, append([]string{"check", f.srv.URL + "/mcp", "--auth", "authorization-code", "--phases", "net,discovery,auth"}, fastFlags()...)...)
	if code != 2 || !strings.Contains(out, "passmcp login") {
		t.Errorf("check without stored token: %d\n%s", code, out)
	}
}

func TestConfigCommands(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	out, code := run(t, "config", "init")
	if code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("init: %d %s", code, out)
	}
	if _, code := run(t, "config", "init"); code != 1 {
		t.Error("second init must refuse")
	}
	out, code = run(t, "config", "validate")
	if code != 0 || !strings.Contains(out, "ok (0 defaults, 0 profiles)") {
		t.Errorf("validate: %d %s", code, out)
	}
	out, code = run(t, "config", "show")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("show: %d %s", code, out)
	}
	p := filepath.Join(xdg, "passmcp", "config.json")
	_ = os.WriteFile(p, []byte(`{"defaults":{"nope":1}}`), 0o600)
	if _, code := run(t, "config", "validate"); code != 1 {
		t.Error("unknown default must fail validate")
	}
	_ = os.WriteFile(p, []byte(`{"profiles":{"a":{"endpoint":"x","settings":{"nope":1}}}}`), 0o600)
	if _, code := run(t, "config", "validate"); code != 1 {
		t.Error("unknown profile setting must fail validate")
	}
	_ = os.WriteFile(p, []byte(`{broken`), 0o600)
	if _, code := run(t, "config", "show"); code != 1 {
		t.Error("broken file must fail show")
	}
	if _, code := run(t, "config", "validate"); code != 1 {
		t.Error("broken file must fail validate")
	}
	// init must be able to create a file that does not exist yet, whether
	// the path comes from PASSMCP_CONFIG or an explicit --config.
	explicit := filepath.Join(xdg, "explicit.json")
	t.Setenv("PASSMCP_CONFIG", explicit)
	if _, code := run(t, "config", "init"); code != 0 {
		t.Error("init with PASSMCP_CONFIG")
	}
	if _, err := os.Stat(explicit); err != nil {
		t.Error("explicit config not written")
	}
	other := filepath.Join(xdg, "other.json")
	if _, code := run(t, "config", "init", "--config", other); code != 0 {
		t.Error("init must accept a --config path that does not exist yet")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("--config path not written by init")
	}
}

func TestVersionAndHelpAndRoot(t *testing.T) {
	out, code := run(t, "version")
	if code != 0 || !strings.Contains(out, "passmcp dev") {
		t.Errorf("version: %d %s", code, out)
	}
	if _, code := run(t, "--help"); code != 0 {
		t.Error("help")
	}
	if _, code := run(t, "check", "--help"); code != 0 {
		t.Error("check help")
	}
	if Root() != rootCmd {
		t.Error("Root accessor")
	}
	if !validOutput("md") || validOutput("xml") {
		t.Error("validOutput")
	}
	allowMutations, onlyTools = true, []string{"a"}
	if p := buildPolicy(); !p.AllowMutations || len(p.Only) != 1 {
		t.Error("buildPolicy")
	}
	resetAll()
	origExit := osExit
	called := 0
	osExit = func(int) { called++ }
	Execute()
	osExit = origExit
	_ = called
}

func TestCurrentTokenNilForStatic(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	resetAll()
	token = "tok-static"
	cr, err := buildCreds()
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := connectWithCreds(rootCmd, engine.TargetSpec{Endpoint: f.srv.URL + "/mcp"}, cr)
	if err != nil {
		t.Fatal(err)
	}
	if currentToken(c) != nil {
		t.Error("static source has no refreshing token")
	}
}

// TestCheckExportsTracesAndStructuredLogs covers the wiring the unit tests
// cannot: that the flags reach the exporter, that the trace id on the
// report is the one the spans carry, and that a collector refusing the
// export does not change what the run reported.
func TestCheckExportsTracesAndStructuredLogs(t *testing.T) {
	f := newFakeServer(t)
	f.open = true

	type received struct {
		hdr  http.Header
		body []byte
	}
	got := make(chan received, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- received{hdr: r.Header.Clone(), body: b}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	out, _ := run(t, append([]string{
		"check", f.srv.URL + "/mcp", "--output", "json",
		"--otlp-endpoint", collector.URL + "/v1/traces",
		"--otlp-header", "X-Tenant: acme",
		"--phases", "net,handshake",
	}, fastFlags()...)...)

	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json output: %v\n%s", err, out)
	}
	traceID, _ := rep["trace_id"].(string)
	if len(traceID) != 32 {
		t.Fatalf("report trace_id = %q", traceID)
	}

	select {
	case r := <-got:
		if r.hdr.Get("X-Tenant") != "acme" {
			t.Errorf("--otlp-header did not reach the collector: %q", r.hdr.Get("X-Tenant"))
		}
		if r.hdr.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.hdr.Get("Content-Type"))
		}
		if !strings.Contains(string(r.body), traceID) {
			t.Errorf("the spans do not carry the report's trace id %s", traceID)
		}
		if !strings.Contains(string(r.body), `"name":"passmcp check"`) {
			t.Errorf("no root span in the payload:\n%s", r.body)
		}
		if !strings.Contains(string(r.body), `"name":"phase net"`) {
			t.Errorf("no phase span in the payload:\n%s", r.body)
		}
	default:
		t.Fatal("the collector received nothing")
	}
}

// TestStructuredLogsCarryTheRunsTraceID is why the trace id is settled in
// the CLI rather than generated inside probe.Run: the whole point of
// structured diagnostics is joining a log line to the report it came from,
// and an id invented after the fact joins nothing.
func TestStructuredLogsCarryTheRunsTraceID(t *testing.T) {
	f := newFakeServer(t)
	f.open = true

	out, errOut, _ := runCapturingStderr(t, "check", f.srv.URL+"/mcp",
		"--output", "json", "--phases", "net,handshake",
		"--log-format", "json", "--log-level", "info",
		"--rps", "0", "--samples", "1", "--concurrency", "2")

	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json output: %v\n%s", err, out)
	}
	traceID, _ := rep["trace_id"].(string)
	if len(traceID) != 32 {
		t.Fatalf("report trace_id = %q", traceID)
	}

	var lines int
	for _, line := range strings.Split(strings.TrimSpace(errOut), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("diagnostic line is not JSON: %v\n%s", err, line)
		}
		lines++
		if rec["trace_id"] != traceID {
			t.Errorf("log line carries trace_id %v, report says %s", rec["trace_id"], traceID)
		}
		if rec["msg"] == nil || rec["level"] == nil {
			t.Errorf("line is missing msg or level: %s", line)
		}
	}
	if lines == 0 {
		t.Fatalf("no structured diagnostics were written:\n%s", errOut)
	}
}

// TestCheckSurvivesADeadCollector is the promise the CLI makes: a
// telemetry backend being down is not a finding about the server, and must
// not turn a completed run into a failed one.
func TestCheckSurvivesADeadCollector(t *testing.T) {
	f := newFakeServer(t)
	f.open = true

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	out, code := run(t, append([]string{
		"check", f.srv.URL + "/mcp", "--output", "json",
		"--otlp-endpoint", dead.URL + "/v1/traces",
		"--phases", "net,handshake",
	}, fastFlags()...)...)

	if code != 0 {
		t.Errorf("exit = %d; a dead collector must not change the verdict", code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("the report was not produced: %v\n%s", err, out)
	}
}

// TestLoginRejectsMixUpIssuer: a redirect whose RFC 9207 iss names another
// authorization server is the mix-up attack, where a malicious server relays
// a code an honest one minted. login must refuse it rather than drop iss.
func TestLoginRejectsMixUpIssuer(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	code, stderr := loginWithRedirect(t, f.srv.URL+"/mcp", "18979", func(s string) string {
		if st := stateFrom(s); st != "" {
			return "code=the-code&state=" + st + "&iss=https%3A%2F%2Fmix-up.invalid"
		}
		return ""
	})
	if code != 1 || !strings.Contains(stderr, "mix-up.invalid") {
		t.Errorf("a redirect from another issuer should be refused, got %d\n%s", code, stderr)
	}
}

// TestLoginAcceptsMatchingIssuer: the same redirect with the issuer the code
// was requested from completes, so the check refuses only a mix-up.
func TestLoginAcceptsMatchingIssuer(t *testing.T) {
	f := newFakeServer(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	code, stderr := loginWithRedirect(t, f.srv.URL+"/mcp", "18980", func(s string) string {
		if st := stateFrom(s); st != "" {
			return "code=the-code&state=" + st + "&iss=" + url.QueryEscape(f.srv.URL+"/as")
		}
		return ""
	})
	if code != 0 || !strings.Contains(stderr, "token stored in") {
		t.Errorf("the issuer's own redirect should complete, got %d\n%s", code, stderr)
	}
}
