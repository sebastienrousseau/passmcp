// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Mask replaces secret material in output.
const Mask = "***"

// Redactor scrubs known secrets and secret-bearing fields from strings,
// headers and URLs before they reach a report or a log.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
	// personal holds personal-data values registered from result-bearing
	// responses (see personal.go), masked like secrets.
	personal []string

	// cmu guards counts, which String updates while holding mu for
	// reading.
	cmu    sync.Mutex
	counts map[string]int
}

// sensitiveHeaders are always masked regardless of value.
var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
}

// sensitiveParams are query or form parameters whose values are masked.
var sensitiveParams = map[string]bool{
	"code": true, "state": true, "access_token": true, "refresh_token": true, "client_secret": true,
	"code_verifier": true, "token": true, "api_key": true, "apikey": true, "password": true,
}

// Add registers a secret value. Empty and very short values are ignored so
// the redactor cannot be tricked into masking every "a".
func (r *Redactor) Add(secret string) {
	if len(secret) < 4 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.secrets {
		if s == secret {
			return
		}
	}
	r.secrets = append(r.secrets, secret)
	// Longest first so a secret that contains another is masked whole.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

// String masks registered secrets inside s.
func (r *Redactor) String(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, Mask)
		if esc := url.QueryEscape(sec); esc != sec {
			s = strings.ReplaceAll(s, esc, Mask)
		}
	}
	return r.maskPersonalValues(s)
}

// Header masks a header value by name policy, then by registered secrets.
func (r *Redactor) Header(name, value string) string {
	lname := strings.ToLower(name)
	if sensitiveHeaders[lname] || strings.Contains(lname, "secret") || strings.Contains(lname, "token") || strings.Contains(lname, "key") {
		return maskKeepScheme(value)
	}
	return r.String(value)
}

// maskKeepScheme keeps "Bearer"/"Basic" so the report shows the scheme.
func maskKeepScheme(v string) string {
	if i := strings.IndexByte(v, ' '); i > 0 && i < 12 {
		return v[:i] + " " + Mask
	}
	return Mask
}

// URL masks sensitive query parameters and registered secrets in a URL.
func (r *Redactor) URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return r.String(raw)
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), Mask)
	}
	q := u.Query()
	changed := false
	for k := range q {
		if sensitiveParams[strings.ToLower(k)] {
			q.Set(k, Mask)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return r.String(u.String())
}

// sensitiveJSONKeys are masked inside JSON bodies and their values
// registered as secrets, so a token issued mid-run is masked everywhere it
// appears afterwards.
var sensitiveJSONKeys = map[string]bool{
	"access_token": true, "refresh_token": true, "id_token": true, "client_secret": true,
	"registration_access_token": true, "code": true, "code_verifier": true, "password": true, "api_key": true, "secret": true,
}

// JSON masks sensitive keys in a JSON document (recursively) and registers
// their values. Non-JSON input is returned through String.
func (r *Redactor) JSON(body []byte) string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return r.String(string(body))
	}
	v = r.maskValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return r.String(string(body))
	}
	return r.String(string(out))
}

func (r *Redactor) maskValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitiveJSONKeys[strings.ToLower(k)] {
				if s, ok := val.(string); ok {
					r.Add(s)
				}
				t[k] = Mask
				continue
			}
			t[k] = r.maskValue(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = r.maskValue(t[i])
		}
		return t
	}
	return v
}

// JSONOrKeys masks a JSON body by key, falling back to a textual sweep for
// sensitive key names when the body does not parse — which is what happens
// to a body truncated at the capture cap. Without the fallback a token in a
// body larger than the cap would reach the report in the clear.
func (r *Redactor) JSONOrKeys(body []byte) string {
	var v any
	if json.Unmarshal(body, &v) == nil {
		return r.JSON(body)
	}
	return r.String(r.maskJSONKeysTextually(string(body)))
}

// maskJSONKeysTextually replaces the value following any sensitive key in a
// JSON-ish document, registering each value it finds as a secret. It works
// on invalid JSON precisely because it never parses: it scans for
// "key" : "value" and rewrites the value.
func (r *Redactor) maskJSONKeysTextually(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		q := strings.IndexByte(s[i:], '"')
		if q < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		q += i
		end := closingQuote(s, q+1)
		if end >= len(s) {
			b.WriteString(s[i:])
			return b.String()
		}
		key := s[q+1 : end]
		b.WriteString(s[i : end+1])
		i = end + 1
		if !sensitiveJSONKeys[strings.ToLower(key)] {
			continue
		}
		// Skip whitespace and the colon, then mask the value that follows.
		j, ok := stringValueAfterKey(s, i)
		if !ok {
			continue
		}
		vEnd := closingQuote(s, j+1)
		r.Add(s[j+1 : min(vEnd, len(s))])
		b.WriteString(s[i:j])
		b.WriteString(`"` + Mask + `"`)
		if vEnd < len(s) {
			i = vEnd + 1
		} else {
			i = len(s)
		}
	}
	return b.String()
}

// closingQuote returns the index of the quote that closes a JSON string
// whose contents start at from, stepping over backslash escapes. It is
// len(s) or beyond when the string is unterminated.
func closingQuote(s string, from int) int {
	end := from
	for end < len(s) && s[end] != '"' {
		if s[end] == '\\' {
			end++
		}
		end++
	}
	return end
}

// stringValueAfterKey finds the opening quote of a string value that
// follows a key ending at i: optional whitespace, a colon, optional
// whitespace, then '"'. ok is false for anything else, including a value
// that is not a string.
func stringValueAfterKey(s string, i int) (int, bool) {
	j := skipJSONSpace(s, i)
	if j >= len(s) || s[j] != ':' {
		return 0, false
	}
	j = skipJSONSpace(s, j+1)
	if j >= len(s) || s[j] != '"' {
		return 0, false
	}
	return j, true
}

// skipJSONSpace returns the first index at or after j that is not JSON
// whitespace.
func skipJSONSpace(s string, j int) int {
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
		j++
	}
	return j
}

// Form masks sensitive keys in an x-www-form-urlencoded body.
func (r *Redactor) Form(body string) string {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return r.String(body)
	}
	for k := range vals {
		if sensitiveParams[strings.ToLower(k)] {
			vals.Set(k, Mask)
		}
	}
	return r.String(vals.Encode())
}
