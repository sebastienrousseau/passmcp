// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"errors"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Secret material the curl tests plant. None of it may survive into a
// command, whether the event was redacted when recorded or not.
const (
	curlToken    = "issued-token-curl"
	curlAPIKey   = "key-SECRET-abcdef"
	curlClientSc = "cs-SECRET-xyz987"
	curlRefresh  = "rt-SECRET-555"
	curlCookie   = "sid=cookie-SECRET-42"
)

// rawEvent is an event as it would look had nothing redacted it: the
// worst case, a report written by something other than the recorder.
func rawEvent() Event {
	return Event{
		Seq: 7, Method: "POST",
		URL: "https://mcp.example.com/mcp?access_token=" + curlToken + "&page=2",
		RequestHeaders: map[string]string{
			"Authorization":  "Bearer " + curlToken,
			"X-Api-Key":      curlAPIKey,
			"Cookie":         curlCookie,
			"Content-Type":   "application/json",
			"Content-Length": "99",
			"X-Note":         "echo " + curlToken,
		},
		RequestBytes: 99,
		RequestBody:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"refresh_token":"` + curlRefresh + `","note":"it's ` + curlToken + `"}}`,
	}
}

// TestCurlNeverCarriesASecret is ADR-0003 applied to the reproducer: the
// event passes through the redactor by name, structurally and by value,
// and every masked value becomes a placeholder.
func TestCurlNeverCarriesASecret(t *testing.T) {
	red := &Redactor{}
	red.Add(curlToken)
	cc, err := Curl(rawEvent(), red)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{curlToken, curlAPIKey, curlClientSc, curlRefresh, "cookie-SECRET"} {
		if strings.Contains(cc.Command, secret) {
			t.Errorf("secret %q reached the command:\n%s", secret, cc.Command)
		}
	}
	for _, want := range []string{`'Authorization: Bearer '"${PASSMCP_TOKEN}"`, `'X-Api-Key: '"${PASSMCP_X_API_KEY}"`, `"${PASSMCP_REFRESH_TOKEN}"`, "page=2"} {
		if !strings.Contains(cc.Command, want) {
			t.Errorf("command lacks %s:\n%s", want, cc.Command)
		}
	}
	if strings.Contains(cc.Command, "Content-Length") {
		t.Error("Content-Length is curl's to compute, not the reproducer's")
	}
	if !slices.Contains(cc.Variables, "PASSMCP_TOKEN") || !slices.IsSorted(cc.Variables) {
		t.Errorf("variables = %v", cc.Variables)
	}
}

// TestCurlMasksAFormBody the way the recorder does, and names the
// placeholder after the parameter.
func TestCurlMasksAFormBody(t *testing.T) {
	ev := Event{
		Method: "POST", URL: "https://as.example.com/token",
		RequestHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		RequestBody:    "grant_type=client_credentials&client_secret=" + curlClientSc,
		RequestBytes:   60,
	}
	cc, err := Curl(ev, &Redactor{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cc.Command, curlClientSc) || !strings.Contains(cc.Command, `client_secret='"${PASSMCP_CLIENT_SECRET}"`) {
		t.Errorf("form body not masked into a placeholder:\n%s", cc.Command)
	}
}

// TestCurlCommandRunsInAShell: the quoting is proved by a shell, not by
// reading it. A stand-in curl prints the arguments it received, and the
// placeholder is expanded from the environment.
func TestCurlCommandRunsInAShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	cc, err := Curl(rawEvent(), &Redactor{})
	if err != nil {
		t.Fatal(err)
	}
	script := `curl() { for a in "$@"; do printf '%s\n' "$a"; done; }
` + cc.Command
	cmd := exec.Command(sh, "-c", script)
	cmd.Env = []string{"PASSMCP_TOKEN=from-env", "PASSMCP_X_API_KEY=k", "PASSMCP_COOKIE=c", "PASSMCP_REFRESH_TOKEN=r"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the command does not run: %v\n%s\n%s", err, cc.Command, out)
	}
	args := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for _, want := range []string{"Authorization: Bearer from-env", "X-Api-Key: k", "Cookie: c", "POST"} {
		if !slices.Contains(args, want) {
			t.Errorf("curl did not receive %q; got %q", want, args)
		}
	}
	// The apostrophe in the body survives the quoting.
	if !strings.Contains(string(out), `"note":"it's `) {
		t.Errorf("the body lost its apostrophe:\n%s", out)
	}
}

// TestCurlRefusesAPipe: a stdio exchange has no HTTP request, and a curl
// line for it would be an invention.
func TestCurlRefusesAPipe(t *testing.T) {
	_, err := Curl(Event{Method: PipeMethod, URL: "stdio:npx server"}, &Redactor{})
	if !errors.Is(err, ErrNotHTTP) {
		t.Errorf("err = %v, want ErrNotHTTP", err)
	}
}

// TestCurlSaysWhatItCannotReproduce rather than guessing a body.
func TestCurlSaysWhatItCannotReproduce(t *testing.T) {
	for name, ev := range map[string]Event{
		"--capture-bodies": {Method: "POST", URL: "https://x/mcp", RequestBytes: 42},
		"truncated":        {Method: "POST", URL: "https://x/mcp", RequestBytes: 99999, RequestBody: `{"a":1…[truncated 99000 bytes]`},
	} {
		cc, err := Curl(ev, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(cc.Command, "--data-raw") || len(cc.Notes) != 1 || !strings.Contains(cc.Notes[0], name) {
			t.Errorf("%s: %+v", name, cc)
		}
	}
}

// TestAPlainGETNeedsNothing: no notes, no variables, no body.
func TestAPlainGETNeedsNothing(t *testing.T) {
	cc, err := Curl(Event{Method: "GET", URL: "https://x/.well-known/oauth-protected-resource"}, nil)
	if err != nil || len(cc.Notes) != 0 || len(cc.Variables) != 0 || strings.Contains(cc.Command, "--data-raw") {
		t.Errorf("a plain GET: %+v %v", cc, err)
	}
}

// TestPlaceholderNamesComeFromWhereTheSecretSat.
func TestPlaceholderNamesComeFromWhereTheSecretSat(t *testing.T) {
	for prefix, want := range map[string]string{
		"Authorization: Bearer ":   "PASSMCP_TOKEN",
		"Authorization: Basic ":    "PASSMCP_BASIC_CREDENTIALS",
		"Authorization: DPoP ":     "PASSMCP_DPOP_TOKEN",
		"X-Api-Key: ":              "PASSMCP_X_API_KEY",
		"https://x/?access_token=": "PASSMCP_TOKEN",
		"a=1&client_secret=":       "PASSMCP_CLIENT_SECRET",
		`{"params":{"api_key":"`:   "PASSMCP_API_KEY",
		`{"id_token" : "`:          "PASSMCP_ID_TOKEN",
		"something ":               "PASSMCP_SECRET",
		"":                         "PASSMCP_SECRET",
	} {
		if got := placeholderFor(prefix); got != want {
			t.Errorf("placeholderFor(%q) = %s, want %s", prefix, got, want)
		}
	}
}

// TestShellWordQuotesEverythingElse, including the characters a shell
// would otherwise act on.
func TestShellWordQuotesEverythingElse(t *testing.T) {
	vars := map[string]bool{}
	for in, want := range map[string]string{
		"":                              "''",
		"plain":                         "'plain'",
		"it's":                          `'it'\''s'`,
		"$(rm -rf /)":                   "'$(rm -rf /)'",
		"a\nb":                          "'a\nb'",
		"Authorization: Bearer " + Mask: `'Authorization: Bearer '"${PASSMCP_TOKEN}"`,
		Mask:                            `"${PASSMCP_SECRET}"`,
	} {
		if got := shellWord(in, vars); got != want {
			t.Errorf("shellWord(%q) = %s, want %s", in, got, want)
		}
	}
}
