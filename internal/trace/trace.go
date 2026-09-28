// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package trace links the acceptance criteria written in passmcp's user-story
// issues to the tests that prove them.
//
// A user story's criteria are its specification. Each has an ID, written in
// the issue as a bold list lead-in:
//
//   - **SOC2-01**: **Given** …, **when** …, **then** …
//
// A test proves a criterion by citing it on the line above its declaration:
//
//	// AC: SOC2-01
//	func TestFindingsCarrySOC2Controls(t *testing.T) { … }
//
// The package reads a committed snapshot of the stories, scans the module's
// tests for citations, and reports which criteria have a test and which do
// not. A closed story with an untested criterion is a failure: the story was
// declared done without the regression test that keeps it done. An open
// story is reported and passes, so a story can land test by test.
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// IDPattern is the shape of a criterion ID: an upper-case prefix, a hyphen
// and two digits, for example SOC2-01 or TRACE-05.
var IDPattern = regexp.MustCompile(`^[A-Z0-9]+-[0-9]{2}$`)

// definition matches an ID where a story defines it: bold, at the start of
// a list item, followed by a colon. Only definitions count. A story's text
// also mentions IDs it does not own (another story's criterion, an example
// in the shared footer, a CVE number), and counting those would invent
// criteria nobody wrote.
var definition = regexp.MustCompile(`(?m)^\s*[-*]\s+\*\*([A-Z0-9]+-[0-9]{2})\*\*:`)

// Story is one user-story issue, as the snapshot records it.
type Story struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"` // "open" or "closed"
	Body   string `json:"body"`
}

// home is a story's owning repository, when the issue names one on its own
// line: "**Repository:** owner/name". Stories without it belong to the
// repository whose tracker holds them.
var home = regexp.MustCompile(`(?m)^\*\*Repository:\*\*\s*(\S+)\s*$`)

// Home returns the repository that implements the story, or "" when the
// issue does not name one.
func (s Story) Home() string {
	if m := home.FindStringSubmatch(s.Body); m != nil {
		return m[1]
	}
	return ""
}

// Closed reports whether the story has been declared done.
func (s Story) Closed() bool { return strings.EqualFold(s.State, "closed") }

// Criteria returns the IDs the story defines, in the order it defines them,
// each once.
func (s Story) Criteria() []string {
	var ids []string
	seen := map[string]bool{}
	for _, m := range definition.FindAllStringSubmatch(s.Body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			ids = append(ids, m[1])
		}
	}
	return ids
}

// LoadStories reads a snapshot written by Snapshot.
func LoadStories(path string) ([]Story, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the snapshot path is the operator's own flag
	if err != nil {
		return nil, err
	}
	var stories []Story
	if err := json.Unmarshal(b, &stories); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return stories, nil
}

// issue is the part of a GitHub issue the snapshot keeps.
type issue struct {
	Number      int             `json:"number"`
	Title       string          `json:"title"`
	State       string          `json:"state"`
	Body        string          `json:"body"`
	PullRequest json.RawMessage `json:"pull_request"`
}

// Snapshot turns GitHub's issue listing (one or more JSON arrays, as
// `gh api --paginate` prints them) into the committed snapshot: pull
// requests dropped, sorted by number, indented so a refresh diffs cleanly.
func Snapshot(listing []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(listing))
	var stories []Story
	for dec.More() {
		var page []issue
		if err := dec.Decode(&page); err != nil {
			return nil, fmt.Errorf("issue listing: %w", err)
		}
		for _, is := range page {
			if len(is.PullRequest) > 0 && string(is.PullRequest) != "null" {
				continue
			}
			stories = append(stories, Story{Number: is.Number, Title: is.Title, State: is.State, Body: is.Body})
		}
	}
	sort.Slice(stories, func(i, j int) bool { return stories[i].Number < stories[j].Number })
	out, err := json.MarshalIndent(stories, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
