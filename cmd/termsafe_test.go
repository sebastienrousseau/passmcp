// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/watch"
)

// hostileText is content a server could return to rewrite the operator's
// terminal: clear it, retitle the window, overwrite the current line.
const hostileText = "\x1b[2J\x1b]0;owned\x07\rok\u009b1A"

func assertNoTerminalControls(t *testing.T, where, out string) {
	t.Helper()
	if i := strings.IndexAny(out, "\x1b\r\a\u009b"); i >= 0 {
		t.Errorf("%s carries a control character at %d: %q", where, i, out[max(0, i-20):min(len(out), i+20)])
	}
}

// TestTextOutputsNeutraliseServerText covers every text rendering of what
// a server returned: call, read, prompt and watch. Each is written to a
// terminal as often as not.
func TestTextOutputsNeutraliseServerText(t *testing.T) {
	var call, read, prompt, pulse bytes.Buffer
	writeCallResult(&call, "tool"+hostileText, time.Millisecond, &passmcp.CallToolResult{
		Content: []passmcp.Content{{Type: "text", Text: "result" + hostileText}, {Type: "image" + hostileText, MimeType: "x" + hostileText}},
	})
	writeResource(&read, "fake://doc"+hostileText, time.Millisecond, &passmcp.ReadResourceResult{Contents: []passmcp.ResourceContents{
		{URI: "fake://doc", Text: "body" + hostileText},
		{URI: "fake://bin" + hostileText, Blob: "AAAA", MimeType: "m" + hostileText},
	}})
	writePrompt(&prompt, "p", time.Millisecond, &passmcp.GetPromptResult{
		Description: "desc" + hostileText,
		Messages:    []passmcp.PromptMessage{{Role: "user" + hostileText, Content: passmcp.Content{Type: "text", Text: "say" + hostileText}}},
	})
	ww := newWatchWriter(engine.FormatText, &pulse)
	ww.event(watch.Event{Kind: "error", Target: "t", Detail: "could not reach the server: " + hostileText, Status: "transport_error"})
	ww.event(watch.Event{Kind: "drift", Target: "t", Detail: "1 change", Changes: nil})
	for name, out := range map[string]string{"call": call.String(), "read": read.String(), "prompt": prompt.String(), "watch": pulse.String()} {
		assertNoTerminalControls(t, name, out)
	}
	for name, pair := range map[string][2]string{
		"call": {call.String(), "result"}, "read": {read.String(), "body"},
		"prompt": {prompt.String(), "say"}, "watch": {pulse.String(), "could not reach"},
	} {
		if !strings.Contains(pair[0], pair[1]) {
			t.Errorf("%s output lost its text:\n%s", name, pair[0])
		}
	}
}

// TestCommandErrorNeutralisesServerText: the error a command ends with is
// the last thing printed, and often quotes an authorization server.
func TestCommandErrorNeutralisesServerText(t *testing.T) {
	var b bytes.Buffer
	writeCommandError(&b, errors.New("authorization server returned access_denied: "+hostileText))
	assertNoTerminalControls(t, "command error", b.String())
	if !strings.HasPrefix(b.String(), "passmcp: authorization server returned access_denied: ") {
		t.Errorf("error line = %q", b.String())
	}
}

// TestWatchNDJSONKeepsServerTextFaithful: the machine rendering is owed
// exactly what the server said, and its encoder escapes it.
func TestWatchNDJSONKeepsServerTextFaithful(t *testing.T) {
	var out bytes.Buffer
	ww := newWatchWriter(engine.FormatNDJSON, &out)
	ww.event(watch.Event{Kind: "error", Target: "t", Detail: "said " + hostileText})
	var ev watch.Event
	if err := json.Unmarshal(out.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Detail != "said "+hostileText || bytes.ContainsRune(out.Bytes(), 0x1b) {
		t.Errorf("ndjson = %q", out.String())
	}
}
