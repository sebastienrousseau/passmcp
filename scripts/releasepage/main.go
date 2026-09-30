// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command releasepage composes a GitHub release page in the passmcp family's
// layout and, with -publish, puts it on the release.
//
// The layout is the portfolio's release page format: the title
// "<name> <version>"; the hand-written "## Highlights ⭐️" from the
// committed highlights file; GitHub's generated "## What's Changed" (and
// "## New Contributors" when there are any); a "## Checksums" section with
// the SHA-256 of every asset attached to the release; and GitHub's
// "**Full Changelog**" line last. Only the highlights are written by hand;
// the rest is generated here from the release as published, so no page has
// to be rewritten after a release.
//
//	go run ./scripts/releasepage -name passmcp -tag v0.0.3            # print
//	go run ./scripts/releasepage -name passmcp -tag v0.0.4 -publish   # publish
//
// Without -publish nothing is written to GitHub: the title goes to stderr
// and the notes to stdout. The generated section comes from GitHub's
// generate-notes API, so even a dry run needs a gh token with contents
// access. Assets named on the command line are hashed instead of the
// release's own, which is how a dry run checks the page for artefacts that
// were built but never uploaded.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// highlightsHeading opens the only hand-written section.
const highlightsHeading = "## Highlights ⭐️"

// fullChangelog opens the line GitHub ends its generated notes with.
const fullChangelog = "**Full Changelog**"

// noAssets is what the checksums section says when there is nothing to hash.
const noAssets = "This release attaches no downloadable assets."

// runner runs the gh command line; tests replace it.
type runner interface {
	Run(args ...string) ([]byte, error)
}

// ghCLI is the real gh on PATH.
type ghCLI struct{}

// Run runs gh with args and returns its stdout; gh's stderr is passed through.
func (ghCLI) Run(args ...string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), "gh", args...) // #nosec G204 -- fixed binary; arguments are the operator's
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// options is the parsed command line.
type options struct {
	tag, name, repo, highlights string
	previous, target, note      string
	latest, publish             bool
	assets                      []string
}

// asset is one line of the checksums section.
type asset struct{ name, sum string }

func main() {
	os.Exit(run(os.Args[1:], ghCLI{}, os.Stdout, os.Stderr))
}

// run is main without the process: it returns the exit status.
func run(args []string, gh runner, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if err != nil {
		return 2
	}
	if err := release(o, gh, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "releasepage: %v\n", err)
		return 1
	}
	return 0
}

// parse reads the flags; the arguments left over are asset files.
func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("releasepage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.tag, "tag", "", "the release tag (required)")
	fs.StringVar(&o.name, "name", "", "the project name the title starts with (required)")
	fs.StringVar(&o.repo, "repo", os.Getenv("GITHUB_REPOSITORY"), "owner/repo; default: $GITHUB_REPOSITORY, else the checkout's")
	fs.StringVar(&o.highlights, "highlights", "", "the highlights file (default docs/releases/<tag>.md)")
	fs.StringVar(&o.previous, "previous", "", "the tag the generated notes start from (default: GitHub's choice)")
	fs.StringVar(&o.target, "target", "", "the commit a tag that does not exist yet would point at (dry runs)")
	fs.StringVar(&o.note, "note", "", "a paragraph after the no-assets sentence, e.g. an image digest")
	fs.BoolVar(&o.latest, "latest", true, "let GitHub mark the release latest; false for a nested module's tag")
	fs.BoolVar(&o.publish, "publish", false, "create or edit the release; without it, print the page")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.assets = fs.Args()
	if o.tag == "" || o.name == "" {
		_, _ = fmt.Fprintln(stderr, "releasepage: -tag and -name are required")
		return o, errors.New("usage")
	}
	if o.highlights == "" {
		o.highlights = filepath.Join("docs", "releases", o.tag+".md")
	}
	return o, nil
}

// release gathers the three inputs, composes the page, and prints or
// publishes it.
func release(o options, gh runner, stdout, stderr io.Writer) error {
	highlights, err := os.ReadFile(o.highlights)
	if err != nil {
		return err
	}
	generated, err := gh.Run(notesArgs(o)...)
	if err != nil {
		return fmt.Errorf("generate-notes for %s: %w", o.tag, err)
	}
	dir, err := os.MkdirTemp("", "releasepage")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	exists, files, err := assetFiles(o, gh, dir)
	if err != nil {
		return err
	}
	sums, err := checksums(files)
	if err != nil {
		return err
	}
	body, err := compose(string(highlights), string(generated), sums, o.note)
	if err != nil {
		return err
	}
	if !o.publish {
		_, _ = fmt.Fprintf(stderr, "title: %s\n", title(o))
		_, err = io.WriteString(stdout, body)
		return err
	}
	return publish(o, gh, exists, body, dir)
}

// title is "<name> <version>", the version without its v and without a
// nested module's path prefix.
func title(o options) string {
	v := o.tag[strings.LastIndex(o.tag, "/")+1:]
	return o.name + " " + strings.TrimPrefix(v, "v")
}

// withRepo adds -R when the repository is known; gh infers it otherwise.
func withRepo(o options, args ...string) []string {
	if o.repo == "" {
		return args
	}
	return append(args, "-R", o.repo)
}

// notesArgs asks GitHub's generate-notes API for the release's body.
func notesArgs(o options) []string {
	repo := o.repo
	if repo == "" {
		repo = "{owner}/{repo}"
	}
	args := []string{"api", "repos/" + repo + "/releases/generate-notes", "-f", "tag_name=" + o.tag}
	if o.previous != "" {
		args = append(args, "-f", "previous_tag_name="+o.previous)
	}
	if o.target != "" {
		args = append(args, "-f", "target_commitish="+o.target)
	}
	return append(args, "--jq", ".body")
}

// assetFiles returns whether the release exists and the files to hash: the
// ones on the command line if any, else the release's own, downloaded.
func assetFiles(o options, gh runner, dir string) (bool, []string, error) {
	out, err := gh.Run(withRepo(o, "release", "view", o.tag, "--json", "assets", "--jq", ".assets[].name")...)
	exists := err == nil
	if len(o.assets) > 0 || !exists || strings.TrimSpace(string(out)) == "" {
		return exists, o.assets, nil
	}
	dl := filepath.Join(dir, "assets")
	if _, err := gh.Run(withRepo(o, "release", "download", o.tag, "-D", dl)...); err != nil {
		return exists, nil, fmt.Errorf("download the assets of %s: %w", o.tag, err)
	}
	var files []string
	for _, name := range strings.Fields(string(out)) {
		files = append(files, filepath.Join(dl, name))
	}
	return exists, files, nil
}

// checksums hashes each file, sorted by name as a byte string.
func checksums(files []string) ([]asset, error) {
	sums := make([]asset, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 G703 -- the operator's or the release's own asset
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		sums = append(sums, asset{filepath.Base(f), hex.EncodeToString(h[:])})
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i].name < sums[j].name })
	return sums, nil
}

// compose builds the page body from its parts.
func compose(highlights, generated string, sums []asset, note string) (string, error) {
	i := strings.Index(highlights, highlightsHeading)
	if i < 0 || (i > 0 && highlights[i-1] != '\n') {
		return "", fmt.Errorf("the highlights file has no %q heading", highlightsHeading)
	}
	changes, full := splitGenerated(generated)
	if full == "" {
		return "", fmt.Errorf("GitHub's generated notes have no %s line", fullChangelog)
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(highlights[i:]) + "\n\n")
	if changes != "" {
		b.WriteString(changes + "\n\n")
	}
	b.WriteString("## Checksums\n\n" + checksumBody(sums, note) + "\n\n")
	b.WriteString(full + "\n")
	return b.String(), nil
}

// splitGenerated separates GitHub's notes from their Full Changelog line
// and folds the runs of blank lines GitHub leaves between sections.
func splitGenerated(generated string) (changes, full string) {
	var kept []string
	blank := true
	for _, line := range strings.Split(strings.ReplaceAll(generated, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " \t")
		switch {
		case strings.HasPrefix(line, fullChangelog):
			full = line
		case line == "" && blank:
		default:
			kept = append(kept, line)
			blank = line == ""
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n")), full
}

// checksumBody is the fenced SHA-256 list, or the no-assets sentence and
// the note that says what is published instead.
func checksumBody(sums []asset, note string) string {
	if len(sums) == 0 {
		if note = strings.TrimSpace(note); note != "" {
			return noAssets + "\n\n" + note
		}
		return noAssets
	}
	lines := []string{"SHA-256 of every asset attached to this release:", "", "```text"}
	for _, s := range sums {
		lines = append(lines, s.sum+"  "+s.name)
	}
	return strings.Join(append(lines, "```"), "\n")
}

// publish creates the release, or rewrites the one goreleaser made, then
// reads the page back and fails unless it is the page composed here.
func publish(o options, gh runner, exists bool, body, dir string) error {
	notes := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(notes, []byte(body), 0o600); err != nil {
		return err
	}
	args := []string{"release", "edit", o.tag}
	if !exists {
		args = []string{"release", "create", o.tag, "--verify-tag"}
	}
	args = append(args, "--title", title(o), "--notes-file", notes)
	if !o.latest {
		args = append(args, "--latest=false")
	}
	if _, err := gh.Run(withRepo(o, args...)...); err != nil {
		return fmt.Errorf("publish %s: %w", o.tag, err)
	}
	return verify(o, gh, body)
}

// verify reads the published title and body back from GitHub.
func verify(o options, gh runner, body string) error {
	got, err := gh.Run(withRepo(o, "release", "view", o.tag, "--json", "name,body", "--jq", ".name + \"\\n\" + .body")...)
	if err != nil {
		return fmt.Errorf("read back %s: %w", o.tag, err)
	}
	want := title(o) + "\n" + body
	if strings.TrimSpace(strings.ReplaceAll(string(got), "\r\n", "\n")) != strings.TrimSpace(want) {
		return fmt.Errorf("the published page of %s is not the composed one", o.tag)
	}
	return nil
}
