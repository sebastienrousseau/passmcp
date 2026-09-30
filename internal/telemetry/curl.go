// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A reproducer is the request a finding cites, as a command somebody can
// paste into a terminal and send again. It is built from a recorded event,
// and it is shared the way a report is, so it is held to the same rule
// (ADR-0003): everything goes through the Redactor, by name, structurally
// and by value, even though a recorded event was redacted once already.
// A report handed over from elsewhere was not necessarily written by the
// recorder, and running the redactor twice costs nothing.
//
// What the redactor masks does not stay "***". Each masked value becomes a
// shell variable reference named after where it sat ($PASSMCP_TOKEN for a
// bearer token, $PASSMCP_CLIENT_SECRET for a client_secret parameter), so
// the command runs once the operator exports their own credentials, and
// carries none.

// ErrNotHTTP is returned for an exchange that was not an HTTP request: a
// stdio message has no URL, method or headers for curl to send.
var ErrNotHTTP = errors.New("telemetry: a stdio exchange has no HTTP request to reproduce")

// CurlCommand is a recorded request as a curl invocation.
type CurlCommand struct {
	// Command is the curl invocation, one argument group per line with
	// shell continuations. Every argument is single-quoted except the
	// placeholders, which are double-quoted variable references.
	Command string `json:"curl"`
	// Variables are the environment variables the command expects, sorted.
	Variables []string `json:"variables,omitempty"`
	// Notes say what could not be reproduced, such as a body that was not
	// captured.
	Notes []string `json:"notes,omitempty"`
}

// skippedHeaders are computed by curl, and a stale copy would be wrong.
var skippedHeaders = map[string]bool{"content-length": true, "host": true}

// truncatedMarker is what captureBody appends to a body cut at BodyCap.
const truncatedMarker = "…[truncated "

// Curl renders e as a curl command, redacted by red. A nil red is a fresh
// Redactor, which still masks by name and structure.
func Curl(e Event, red *Redactor) (CurlCommand, error) {
	if e.Method == PipeMethod || strings.HasPrefix(e.URL, "stdio:") {
		return CurlCommand{}, ErrNotHTTP
	}
	if red == nil {
		red = &Redactor{}
	}
	vars := map[string]bool{}
	lines := []string{"curl -sS -X " + shellWord(e.Method, vars) + " " + shellWord(red.URL(e.URL), vars)}
	for _, name := range sortedHeaderNames(e.RequestHeaders) {
		v := red.Header(name, e.RequestHeaders[name])
		lines = append(lines, "-H "+shellWord(name+": "+v, vars))
	}
	body, note := curlBody(e, red)
	if body != "" {
		lines = append(lines, "--data-raw "+shellWord(body, vars))
	}
	cc := CurlCommand{Command: strings.Join(lines, " \\\n  ")}
	if note != "" {
		cc.Notes = []string{note}
	}
	for v := range vars {
		cc.Variables = append(cc.Variables, v)
	}
	sort.Strings(cc.Variables)
	return cc, nil
}

// sortedHeaderNames lists the headers to send, in a stable order.
func sortedHeaderNames(h map[string]string) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		if !skippedHeaders[strings.ToLower(k)] {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// curlBody is the request body, redacted as the recorder redacts a
// captured one, or a note saying why there is none to send.
func curlBody(e Event, red *Redactor) (string, string) {
	switch {
	case e.RequestBody == "" && e.RequestBytes > 0:
		return "", fmt.Sprintf("the request body (%d bytes) was not captured; re-run the check with --capture-bodies to reproduce it", e.RequestBytes)
	case e.RequestBody == "":
		return "", ""
	case strings.Contains(e.RequestBody, truncatedMarker):
		return "", "the request body was truncated when it was recorded (--body-cap), so it is not reproduced"
	}
	var s string
	switch ct := strings.ToLower(e.RequestHeaders["Content-Type"]); {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		// Form re-encodes, which escapes the mask itself.
		s = strings.ReplaceAll(red.Form(e.RequestBody), "%2A%2A%2A", Mask)
	case looksJSON([]byte(e.RequestBody)):
		s = red.JSONOrKeys([]byte(e.RequestBody))
	default:
		s = red.String(e.RequestBody)
	}
	return red.maskPersonalPatterns(s), ""
}

// shellWord quotes s as one shell word. Literal text is single-quoted, so
// nothing in it is expanded, whatever a server put there. Each Mask
// becomes a double-quoted variable reference, recorded in vars.
func shellWord(s string, vars map[string]bool) string {
	if s == "" {
		return "''"
	}
	var b strings.Builder
	parts := strings.Split(s, Mask)
	prefix := ""
	for i, p := range parts {
		if p != "" {
			b.WriteString("'" + strings.ReplaceAll(p, "'", `'\''`) + "'")
		}
		prefix += p
		if i == len(parts)-1 {
			break
		}
		name := placeholderFor(prefix)
		vars[name] = true
		b.WriteString(`"${` + name + `}"`)
		prefix += Mask
	}
	return b.String()
}

var (
	// schemeBefore matches an Authorization header's scheme word just
	// before its masked credential.
	schemeBefore = regexp.MustCompile(`(?i)^(?:proxy-)?authorization:\s*([a-z][a-z0-9-]*) $`)
	// headerBefore matches a whole "Name: " with the value masked.
	headerBefore = regexp.MustCompile(`^([A-Za-z0-9-]+):\s*$`)
	// jsonKeyBefore matches "key": " just before a masked JSON string.
	jsonKeyBefore = regexp.MustCompile(`"([^"\\]+)"\s*:\s*"$`)
	// paramBefore matches key= just before a masked query or form value.
	paramBefore = regexp.MustCompile(`(?:^|[?&])([A-Za-z0-9_.-]+)=$`)
)

// placeholderFor names the variable for a masked value from the text
// before it: the authorization scheme, the header, the JSON key or the
// parameter it belonged to. PASSMCP_SECRET when none of those applies.
func placeholderFor(prefix string) string {
	if m := headerBefore.FindStringSubmatch(prefix); m != nil {
		return varName(m[1])
	}
	if m := schemeBefore.FindStringSubmatch(prefix); m != nil {
		return schemeVar(m[1])
	}
	for _, re := range []*regexp.Regexp{jsonKeyBefore, paramBefore} {
		if m := re.FindStringSubmatch(prefix); m != nil {
			return varName(m[1])
		}
	}
	return "PASSMCP_SECRET"
}

// schemeVar names the variable for a credential after a scheme word.
func schemeVar(scheme string) string {
	switch strings.ToLower(scheme) {
	case "bearer":
		return "PASSMCP_TOKEN"
	case "basic":
		return "PASSMCP_BASIC_CREDENTIALS"
	default:
		return varName(scheme + "_token")
	}
}

// varName is PASSMCP_ and name upper-cased, every other character an
// underscore. The access-token spellings share PASSMCP_TOKEN, the variable
// passmcp itself reads a bearer token from.
func varName(name string) string {
	up := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, name)
	if up == "ACCESS_TOKEN" || up == "TOKEN" {
		return "PASSMCP_TOKEN"
	}
	return "PASSMCP_" + up
}
