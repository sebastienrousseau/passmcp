// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"satellion.com/passmcp/internal/pii"
)

// Personal data is masked as data minimisation (GDPR Art. 5(1)(c)): passmcp
// has no use for the e-mail address a tool returned, only for the fact that
// the call succeeded, so it keeps the fact and drops the address.
//
// Two mechanisms, both structural in the sense of ADR 0003:
//
//   - By key. A value under a personal-data key — email, phone, a name
//     field — in a response that carries a result (tools/call,
//     resources/read, prompts/get, tasks/result) is registered and then
//     masked wherever it appears, including inside a text content item that
//     repeats it. Only result-bearing responses: a "name" in tools/list is
//     a tool name and is evidence, not personal data.
//   - By pattern. E-mail addresses and phone numbers are recognisable
//     anywhere, so they are masked in every captured body and in report
//     text whatever key, or no key, they sit under.
//
// A name in free text with no key is not recognisable and is not masked;
// the recorder captures bodies only with --capture-bodies, and that flag's
// help says bodies may hold customer data.

// RedactionSummary counts what was masked, by kind, so a report can show
// that masking happened without showing what was masked.
type RedactionSummary struct {
	// PersonalData counts masked occurrences: "email", "phone", and
	// "field" for a value registered from a personal-data key.
	PersonalData map[string]int `json:"personal_data"`
}

// Total is the number of masked occurrences of every kind.
func (s RedactionSummary) Total() int {
	n := 0
	for _, v := range s.PersonalData {
		n += v
	}
	return n
}

// resultBearing are the methods whose responses carry what a server
// returned to the agent, as opposed to what it says about itself.
var resultBearing = map[string]bool{
	"tools/call": true, "resources/read": true, "prompts/get": true, "tasks/result": true,
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// Three shapes, conservative on purpose: an international number with
	// a leading +, a North American (NNN) NNN-NNNN, and NNN-NNN-NNNN with
	// separators. A bare run of digits is a timestamp or an id far more
	// often than a phone number, and is left alone.
	phoneRe = regexp.MustCompile(`\+\d[\d \-().]{7,}\d|\(\d{3}\)\s?\d{3}[-\s]\d{4}|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b`)
)

// minPersonal is the shortest value registered from a key. Two characters
// would mask every "UK" and "Al" in the report.
const minPersonal = 3

// registerPersonalFromResponse registers the personal values in a response
// body when the request's method carries a result. body may be JSON or a
// text/event-stream whose data lines are JSON.
func (r *Redactor) registerPersonalFromResponse(rpc *RPCInfo, body []byte) {
	if !r.wantsPersonal(rpc) || len(body) == 0 {
		return
	}
	for _, doc := range jsonDocuments(body) {
		var v any
		if json.Unmarshal(doc, &v) == nil {
			r.walkPersonal(v, 0)
		}
	}
}

// registerPersonalFromTree is registerPersonalFromResponse for a JSON body
// the caller has already decoded.
func (r *Redactor) registerPersonalFromTree(rpc *RPCInfo, tree any) {
	if r.wantsPersonal(rpc) {
		r.walkPersonal(tree, 0)
	}
}

// wantsPersonal reports whether a response to rpc carries a result whose
// personal values are registered.
func (r *Redactor) wantsPersonal(rpc *RPCInfo) bool {
	return r != nil && rpc != nil && resultBearing[rpc.Method]
}

// jsonDocuments returns the JSON documents in a body: the body itself, or
// each data line of a server-sent event stream.
func jsonDocuments(body []byte) [][]byte {
	if looksJSON(body) {
		return [][]byte{body}
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		if data, ok := bytes.CutPrefix(sc.Bytes(), []byte("data:")); ok {
			if d := bytes.TrimSpace(data); looksJSON(d) {
				out = append(out, append([]byte(nil), d...))
			}
		}
	}
	return out
}

// personalDepth bounds the walk over a server-controlled document.
const personalDepth = 12

func (r *Redactor) walkPersonal(v any, depth int) {
	if depth > personalDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && pii.Key(pii.Normalise(k)) {
				r.addPersonal(s)
				continue
			}
			r.walkPersonal(val, depth+1)
		}
	case []any:
		for _, e := range t {
			r.walkPersonal(e, depth+1)
		}
	case string:
		// A text content item often repeats the structured result as a
		// JSON string. Parse it so the same values are found there too.
		if s := strings.TrimSpace(t); strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
			var inner any
			if json.Unmarshal([]byte(s), &inner) == nil {
				r.walkPersonal(inner, depth+1)
			}
		}
	}
}

// addPersonal registers one personal value.
func (r *Redactor) addPersonal(v string) {
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) < minPersonal || v == Mask {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.personalSet[v] {
		return
	}
	if r.personalSet == nil {
		r.personalSet = map[string]bool{}
	}
	r.personalSet[v] = true
	// Longest first, as for secrets, so "Ada Lovelace" is masked whole
	// before "Ada" could split it.
	at := longestFirstIndex(r.personal, v)
	r.personal = slices.Insert(r.personal, at, v)
	r.personalMask.insert(at, []string{v})
}

// maskPersonalValues masks registered personal values in s. The caller
// holds r.mu for reading.
func (r *Redactor) maskPersonalValues(s string) string {
	s, n := r.personalMask.apply(s)
	if n > 0 {
		r.count("field", n)
	}
	return s
}

// maskPersonalPatterns masks e-mail addresses and phone numbers.
func (r *Redactor) maskPersonalPatterns(s string) string {
	s = emailRe.ReplaceAllStringFunc(s, func(string) string { r.count("email", 1); return Mask })
	return phoneRe.ReplaceAllStringFunc(s, func(string) string { r.count("phone", 1); return Mask })
}

// Text masks registered secrets, registered personal values, e-mail
// addresses and phone numbers in s. It is what server text goes through on
// its way into a report.
func (r *Redactor) Text(s string) string {
	if r == nil || s == "" {
		return s
	}
	return r.maskPersonalPatterns(r.String(s))
}

func (r *Redactor) count(kind string, n int) {
	r.cmu.Lock()
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[kind] += n
	r.cmu.Unlock()
}

// Summary reports what has been masked so far.
func (r *Redactor) Summary() RedactionSummary {
	s := RedactionSummary{PersonalData: map[string]int{}}
	if r == nil {
		return s
	}
	r.cmu.Lock()
	for k, v := range r.counts {
		s.PersonalData[k] = v
	}
	r.cmu.Unlock()
	return s
}
