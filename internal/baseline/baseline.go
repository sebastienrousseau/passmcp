// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package baseline records what a server's catalogue looked like when
// somebody approved it, and says what changed since.
//
// A check tells you a server was sound when you ran it. It cannot tell you
// the server is still the one you reviewed, and that gap is the whole of
// the rug-pull threat: the server that passes review and edits its tool
// descriptions the following week is the one that gets through, because a
// one-shot diagnostic cannot see it by construction.
//
// The data was always there. passmcp produces a complete, redacted snapshot
// of a catalogue on every run and then throws it away; this keeps one and
// compares.
//
// What a diff is worth depends entirely on what changed. A new optional
// property is noise and reporting it loudly is how a drift gate gets
// switched off. An annotation flipping to readOnlyHint: true after
// approval is the shape an attack takes, because it is the flip that makes
// a cautious client — passmcp included — start invoking a tool it previously
// would not. So severity here is by kind, never by count.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
)

// Version is the snapshot format. A file written by a later passmcp is
// refused rather than misread.
const Version = 1

// Snapshot is an approved catalogue.
type Snapshot struct {
	Version int `json:"version"`
	// Endpoint is what was approved, for a reader holding two files.
	Endpoint string `json:"endpoint,omitempty"`
	// Taken is when, in UTC.
	Taken time.Time `json:"taken"`
	// Digest is over the tools, so "did anything change at all" is one
	// string comparison rather than a walk. Milestone 12's pulse is this
	// field: two requests, hash, compare.
	Digest string `json:"digest"`
	// Tools is the approved catalogue, keyed by name.
	Tools map[string]Tool `json:"tools"`
}

// Tool is the part of a tool that matters to a reviewer: everything a
// model reads, and the annotations a client acts on.
type Tool struct {
	Description  string          `json:"description,omitempty"`
	Title        string          `json:"title,omitempty"`
	ReadOnly     *bool           `json:"read_only_hint,omitempty"`
	Destructive  *bool           `json:"destructive_hint,omitempty"`
	Idempotent   *bool           `json:"idempotent_hint,omitempty"`
	OpenWorld    *bool           `json:"open_world_hint,omitempty"`
	Required     []string        `json:"required,omitempty"`
	Properties   []string        `json:"properties,omitempty"`
	InputSchema  json.RawMessage `json:"input_schema,omitempty"`
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
}

// Take snapshots a catalogue.
func Take(endpoint string, tools []passmcp.Tool) Snapshot {
	s := Snapshot{
		Version:  Version,
		Endpoint: endpoint,
		Taken:    time.Now().UTC().Truncate(time.Second),
		Tools:    make(map[string]Tool, len(tools)),
	}
	for _, t := range tools {
		bt := Tool{
			Description:  t.Description,
			Title:        t.Title,
			InputSchema:  canonical(t.InputSchema),
			OutputSchema: canonical(t.OutputSchema),
		}
		if t.Annotations != nil {
			bt.ReadOnly = t.Annotations.ReadOnlyHint
			bt.Destructive = t.Annotations.DestructiveHint
			bt.Idempotent = t.Annotations.IdempotentHint
			bt.OpenWorld = t.Annotations.OpenWorldHint
		}
		bt.Required, bt.Properties = schemaShape(t.InputSchema)
		s.Tools[t.Name] = bt
	}
	s.Digest = digest(s.Tools)
	return s
}

// canonical re-encodes a schema so formatting changes are not diffs. A
// server that pretty-prints its JSON one week and minifies it the next has
// changed nothing a model can see.
func canonical(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// schemaShape lifts the required list and the property names out of a
// schema, which is what makes "a constraint was dropped" a diff of its own
// rather than an opaque blob comparison.
func schemaShape(raw json.RawMessage) (required, properties []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	var doc struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil
	}
	required = append(required, doc.Required...)
	sort.Strings(required)
	for k := range doc.Properties {
		properties = append(properties, k)
	}
	sort.Strings(properties)
	return required, properties
}

// digest content-addresses a catalogue, over a deterministic encoding so
// two runs of an unchanged server agree.
func digest(tools map[string]Tool) string {
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, n := range names {
		// A hash.Hash never returns an error; writing the name and a
		// separator so two tools cannot collide by concatenation.
		h.Write([]byte(n))
		h.Write([]byte{0})
		b, err := json.Marshal(tools[n])
		if err != nil {
			continue
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Severity is how much a change matters.
type Severity int

const (
	// Noise is a change with no bearing on what a model does: a new
	// optional property, a longer title.
	Noise Severity = iota
	// Notable is a real change a reviewer should see.
	Notable
	// Serious is a change that alters what a client will do with the tool.
	Serious
	// Critical is the shape a rug pull takes.
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Serious:
		return "serious"
	case Notable:
		return "notable"
	default:
		return "noise"
	}
}

// Change is one difference against the approved snapshot.
type Change struct {
	Tool     string   `json:"tool"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"-"`
	// Detail says what changed, in a sentence a reader can act on.
	Detail string `json:"detail"`
	// Was and Now carry the old and new text where quoting them helps.
	// What changed is the finding, not that something did.
	Was string `json:"was,omitempty"`
	Now string `json:"now,omitempty"`
}

// Diff compares an approved snapshot with what a run just saw.
//
// Ordered worst-first, so a truncated report shows what matters.
func Diff(approved Snapshot, current Snapshot) []Change {
	var out []Change

	names := map[string]bool{}
	for n := range approved.Tools {
		names[n] = true
	}
	for n := range current.Tools {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	for _, name := range sorted {
		was, hadBefore := approved.Tools[name]
		now, hasNow := current.Tools[name]
		switch {
		case !hadBefore:
			// A tool that was not reviewed. This is how an exfiltration
			// tool arrives at a server somebody already trusts.
			out = append(out, Change{
				Tool: name, Kind: "tool-added", Severity: Serious,
				Detail: "a tool that was not in the approved catalogue",
				Now:    truncate(now.Description, 160),
			})
		case !hasNow:
			out = append(out, Change{
				Tool: name, Kind: "tool-removed", Severity: Notable,
				Detail: "a tool in the approved catalogue is gone",
				Was:    truncate(was.Description, 160),
			})
		default:
			out = append(out, compare(name, was, now)...)
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// compare diffs one tool against its approved form.
func compare(name string, was, now Tool) []Change {
	var out []Change

	// The flip that matters. Going to read-only makes a cautious client
	// start invoking a tool it previously refused, which is why it is the
	// direction that escalates rather than the other one.
	if flipped(was.ReadOnly, now.ReadOnly) {
		sev, detail := Notable, "readOnlyHint changed"
		switch {
		case isTrue(now.ReadOnly) && !isTrue(was.ReadOnly):
			sev = Critical
			detail = "readOnlyHint became true after approval, so clients that only call read-only tools will now call this one"
		case !isTrue(now.ReadOnly) && isTrue(was.ReadOnly):
			sev = Serious
			detail = "readOnlyHint was withdrawn; a tool approved as read-only no longer claims to be"
		}
		out = append(out, Change{
			Tool: name, Kind: "annotation", Severity: sev, Detail: detail,
			Was: hintString(was.ReadOnly), Now: hintString(now.ReadOnly),
		})
	}
	if flipped(was.Destructive, now.Destructive) {
		sev := Notable
		if isTrue(was.Destructive) && !isTrue(now.Destructive) {
			sev = Serious
		}
		out = append(out, Change{
			Tool: name, Kind: "annotation", Severity: sev,
			Detail: "destructiveHint changed",
			Was:    hintString(was.Destructive), Now: hintString(now.Destructive),
		})
	}

	if was.Description != now.Description {
		sev, detail := Notable, "the description was edited"
		// A description that has newly acquired text aimed at the model is
		// not an edit, it is an injection into a catalogue somebody
		// already approved. The scanner that reads catalogues at run time
		// reads this one too, so the two cannot disagree.
		if gained := newSignals(was.Description, now.Description); len(gained) > 0 {
			sev = Critical
			detail = "the description gained " + describeKinds(gained)
		}
		out = append(out, Change{
			Tool: name, Kind: "description", Severity: sev, Detail: detail,
			Was: truncate(was.Description, 160), Now: truncate(now.Description, 160),
		})
	}

	if dropped := missing(was.Required, now.Required); len(dropped) > 0 {
		out = append(out, Change{
			Tool: name, Kind: "schema", Severity: Serious,
			Detail: "required argument(s) dropped: " + strings.Join(dropped, ", ") +
				". A widened schema accepts calls the approved one refused",
		})
	}
	if added := missing(now.Required, was.Required); len(added) > 0 {
		out = append(out, Change{
			Tool: name, Kind: "schema", Severity: Notable,
			Detail: "required argument(s) added: " + strings.Join(added, ", "),
		})
	}
	// A new optional property is the canonical example of noise, and is
	// reported as such rather than left out: the point is that it is in
	// the diff and not worth acting on.
	if added := missing(now.Properties, was.Properties); len(added) > 0 {
		out = append(out, Change{
			Tool: name, Kind: "schema", Severity: Noise,
			Detail: properties(len(added)) + " added: " + strings.Join(added, ", "),
		})
	}
	if gone := missing(was.Properties, now.Properties); len(gone) > 0 {
		out = append(out, Change{
			Tool: name, Kind: "schema", Severity: Notable,
			Detail: properties(len(gone)) + " removed: " + strings.Join(gone, ", "),
		})
	}
	return out
}

// newSignals reports the poisoning signals present in the new text and not
// in the old, so a description that was always odd is not re-reported as
// newly odd every run.
func newSignals(was, now string) []diagnostics.SignalKind {
	before := map[diagnostics.SignalKind]bool{}
	for _, s := range diagnostics.ScanText("was", was) {
		before[s.Kind] = true
	}
	seen := map[diagnostics.SignalKind]bool{}
	var out []diagnostics.SignalKind
	for _, s := range diagnostics.ScanText("now", now) {
		if before[s.Kind] || seen[s.Kind] {
			continue
		}
		seen[s.Kind] = true
		out = append(out, s.Kind)
	}
	return out
}

func describeKinds(kinds []diagnostics.SignalKind) string {
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, string(k))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ") + " text it did not carry when it was approved"
}

// properties names the count, in the singular where that is right.
func properties(n int) string {
	if n == 1 {
		return "property"
	}
	return "properties"
}

// missing returns the members of a not present in b.
func missing(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func flipped(a, b *bool) bool {
	if a == nil && b == nil {
		return false
	}
	if a == nil || b == nil {
		return true
	}
	return *a != *b
}

func isTrue(b *bool) bool { return b != nil && *b }

func hintString(b *bool) string {
	if b == nil {
		return "unset"
	}
	if *b {
		return "true"
	}
	return "false"
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Worst returns the highest severity in a set of changes.
func Worst(changes []Change) Severity {
	w := Noise
	for _, c := range changes {
		if c.Severity > w {
			w = c.Severity
		}
	}
	return w
}

// Load reads an approved snapshot.
func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the operator named this file
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("baseline: %s is not a snapshot: %w", path, err)
	}
	if s.Version > Version {
		return nil, fmt.Errorf("baseline: %s was written in format %d and this passmcp reads %d", path, s.Version, Version)
	}
	return &s, nil
}

// Save writes a snapshot, creating the directory if it is missing.
//
// 0600, because a catalogue names the tools an operator can reach and is
// nobody else's business on a shared machine.
func Save(path string, s Snapshot) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
