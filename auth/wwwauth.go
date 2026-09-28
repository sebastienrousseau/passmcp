// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package auth implements the MCP authorization flow: RFC 9110 challenge
// parsing, RFC 9728 protected-resource discovery, RFC 8414 authorization
// server metadata, client registration (Client ID Metadata Documents with
// RFC 7591 dynamic registration as fallback), and OAuth 2.1 token
// acquisition with RFC 8707 resource indicators and PKCE.
package auth

import (
	"strings"
)

// Challenge is one parsed WWW-Authenticate challenge.
type Challenge struct {
	Scheme string
	Params map[string]string // keys lower-cased; token68 stored under "token68"
}

// ParseWWWAuthenticate parses a WWW-Authenticate header value per RFC 9110
// §11.6.1. It handles multiple challenges, quoted strings with escapes,
// token68 values, and arbitrary whitespace. It is lenient with unquoted
// parameter values that contain non-token characters (a common server
// mistake for URLs): such a value runs to the next comma or whitespace.
func ParseWWWAuthenticate(header string) []Challenge {
	var out []Challenge
	s := header
	for {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			return out
		}
		scheme, rest := readToken(s)
		if scheme == "" {
			// Unparsable junk: skip to the next comma.
			if i := strings.IndexByte(s, ','); i >= 0 {
				s = s[i+1:]
				continue
			}
			return out
		}
		ch := Challenge{Scheme: scheme, Params: map[string]string{}}
		s = strings.TrimLeft(rest, " \t")
		if s == "" || s[0] == ',' {
			out = append(out, ch)
			continue
		}
		// token68 or auth-param list?
		if v, rest, ok := readToken68(s); ok {
			ch.Params["token68"] = v
			out = append(out, ch)
			s = rest
			continue
		}
		s = readAuthParams(s, ch.Params)
		out = append(out, ch)
	}
}

// readAuthParams reads a challenge's auth-param list into params and
// returns what follows it: the start of the next challenge, or "".
func readAuthParams(s string, params map[string]string) string {
	for {
		s = strings.TrimLeft(s, " \t")
		key, rest := readToken(s)
		rest = strings.TrimLeft(rest, " \t")
		if key == "" || rest == "" || rest[0] != '=' {
			// Not an auth-param: this is the start of the next challenge.
			return s
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		var val string
		if rest != "" && rest[0] == '"' {
			val, rest = readQuoted(rest)
		} else {
			val, rest = readLenientValue(rest)
		}
		params[strings.ToLower(key)] = val
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return ""
		}
		if rest[0] != ',' {
			return rest
		}
		// After a comma: another param ("k=") or a new challenge?
		peek := strings.TrimLeft(rest[1:], " \t")
		if !startsAuthParam(peek) {
			return peek
		}
		s = peek
	}
}

// startsAuthParam reports whether s opens with a "key=" auth-param rather
// than a new challenge's scheme.
func startsAuthParam(s string) bool {
	if k, r := readToken(s); k != "" {
		if r2 := strings.TrimLeft(r, " \t"); r2 != "" && r2[0] == '=' {
			return true
		}
	}
	return false
}

// FindBearer returns the first Bearer challenge, if any.
func FindBearer(challenges []Challenge) (Challenge, bool) {
	for _, c := range challenges {
		if strings.EqualFold(c.Scheme, "bearer") {
			return c, true
		}
	}
	return Challenge{}, false
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken68Char(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~+/", c) >= 0
}

func readToken(s string) (string, string) {
	i := 0
	for i < len(s) && isTokenChar(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// readToken68 recognises "token68 *'='" followed by whitespace, comma or
// end of input. A single "=" followed by a value is an auth-param, not
// token68.
func readToken68(s string) (string, string, bool) {
	i := 0
	for i < len(s) && isToken68Char(s[i]) {
		i++
	}
	if i == 0 {
		return "", s, false
	}
	j := i
	for j < len(s) && s[j] == '=' {
		j++
	}
	tail := strings.TrimLeft(s[j:], " \t")
	if tail != "" && tail[0] != ',' {
		return "", s, false // "key=value..." shape
	}
	if j == i+1 && tail == "" {
		// "abc=" at end of input: ambiguous; treat as token68.
		return s[:j], tail, true
	}
	if j == i+1 {
		// "abc=," — a param with an empty value is not a valid auth-param
		// either; treat as token68 for robustness.
		return s[:j], tail, true
	}
	return s[:j], tail, true
}

func readLenientValue(s string) (string, string) {
	i := 0
	for i < len(s) && s[i] != ',' && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	return s[:i], s[i:]
}

func readQuoted(s string) (string, string) {
	// s[0] == '"'
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch c {
		case '\\':
			if i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			i++
		case '"':
			return b.String(), s[i+1:]
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), ""
}
