// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are the shapes GitHub's notes and a highlights file take: a
// New Contributors section, the runs of blank lines GitHub leaves, and the
// comment lines a highlights file opens with. They live here rather than in
// testdata/ so that every file in the tree keeps its licence header.
const highlightsMD = `<!-- The licence header a highlights file opens with. -->
<!-- A second comment line. -->

## Highlights ⭐️

* **One thing**: It changed for the user.
* **Another thing**: So did this.

`

const generatedMD = "## What's Changed\n" +
	"* feat: add a check by @alice in https://github.com/o/r/pull/7\n" +
	"* fix(deps): bump x by @dependabot[bot] in https://github.com/o/r/pull/8\n" +
	"\n\n## New Contributors\n" +
	"* @alice made their first contribution in https://github.com/o/r/pull/7\n" +
	"\n\n**Full Changelog**: https://github.com/o/r/compare/v0.0.1...v0.0.2\n"

// assetBodies are the release's assets; their SHA-256 sums were taken with
// `shasum -a 256`, not with the code under test.
var assetBodies = map[string]string{"checksums.txt": "sums\n", "app_Linux_x86_64.tar.gz": "archive\n"}

const hashed = "SHA-256 of every asset attached to this release:\n\n```text\n" +
	"371e16ce98051a3ea7af3eaef8b87d69033154fb5bb33da349d611f0fae061d6  app_Linux_x86_64.tar.gz\n" +
	"c001d0d1d2da2d23b87521529826ff1bb00c6afaac20b652c0871905c84d1508  checksums.txt\n```"

const note = "The image is `ghcr.io/o/r@sha256:0000`."

// wantPage is the page the fixtures make, around a checksums section body.
func wantPage(checksums string) string {
	return "## Highlights ⭐️\n\n" +
		"* **One thing**: It changed for the user.\n" +
		"* **Another thing**: So did this.\n\n" +
		"## What's Changed\n" +
		"* feat: add a check by @alice in https://github.com/o/r/pull/7\n" +
		"* fix(deps): bump x by @dependabot[bot] in https://github.com/o/r/pull/8\n\n" +
		"## New Contributors\n" +
		"* @alice made their first contribution in https://github.com/o/r/pull/7\n\n" +
		"## Checksums\n\n" + checksums + "\n\n" +
		"**Full Changelog**: https://github.com/o/r/compare/v0.0.1...v0.0.2\n"
}

// fixtures writes the highlights file and the assets into a temporary
// directory and returns it.
func fixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"highlights.md": highlightsMD}
	for name, body := range assetBodies {
		files[name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeGH answers the gh calls releasepage makes from the fixtures.
type fakeGH struct {
	calls     [][]string
	assets    []string // names the release view lists
	noRelease bool
	generated string // generate-notes' body; default generatedMD
	failOn    string // a call whose joined args contain this fails
	published string // the title and notes the last create or edit wrote
	tamper    bool   // the read-back returns something else
}

func (f *fakeGH) Run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	joined := strings.Join(args, " ")
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return nil, errors.New("gh failed")
	}
	switch {
	case args[0] == "api":
		return []byte(f.notes()), nil
	case strings.HasPrefix(joined, "release view") && strings.Contains(joined, "assets"):
		if f.noRelease {
			return nil, errors.New("release not found")
		}
		return []byte(strings.Join(f.assets, "\n") + "\n"), nil
	case strings.HasPrefix(joined, "release download"):
		return nil, f.download(args)
	case strings.HasPrefix(joined, "release view"):
		if f.tamper {
			return []byte("something else"), nil
		}
		return []byte(f.published), nil
	}
	return nil, f.write(args)
}

// notes is generate-notes' body.
func (f *fakeGH) notes() string {
	if f.generated == "" {
		return generatedMD
	}
	return f.generated
}

// download writes the listed assets into the -D directory.
func (f *fakeGH) download(args []string) error {
	dir := flagValue(args, "-D")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, name := range f.assets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(assetBodies[name]), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// write records what a create or edit put on the release.
func (f *fakeGH) write(args []string) error {
	b, err := os.ReadFile(flagValue(args, "--notes-file"))
	if err != nil {
		return err
	}
	f.published = flagValue(args, "--title") + "\n" + strings.TrimSpace(string(b))
	return nil
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeGH) called(prefix string) []string {
	for _, c := range f.calls {
		if strings.HasPrefix(strings.Join(c, " "), prefix) {
			return c
		}
	}
	return nil
}

func runPage(t *testing.T, gh *fakeGH, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	base := []string{"-highlights", filepath.Join(fixtures(t), "highlights.md"), "-repo", "o/r"}
	code := run(append(base, args...), gh, &out, &errb)
	return code, out.String(), errb.String()
}

func TestPrintsThePageWithTheReleaseAssetsHashed(t *testing.T) {
	gh := &fakeGH{assets: []string{"checksums.txt", "app_Linux_x86_64.tar.gz"}}
	code, out, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if want := wantPage(hashed); out != want {
		t.Errorf("page:\n%s\nwant:\n%s", out, want)
	}
	if !strings.Contains(errs, "title: app 0.0.2\n") {
		t.Errorf("stderr %q does not give the title", errs)
	}
	if c := gh.called("release edit"); c != nil {
		t.Errorf("a dry run wrote to GitHub: %v", c)
	}
	api := strings.Join(gh.called("api"), " ")
	if !strings.Contains(api, "repos/o/r/releases/generate-notes -f tag_name=v0.0.2") {
		t.Errorf("generate-notes call: %s", api)
	}
}

func TestAssetsOnTheCommandLineAreHashedInsteadOfTheRelease(t *testing.T) {
	gh := &fakeGH{noRelease: true}
	dir := fixtures(t)
	code, out, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2", "-target", "abc123",
		filepath.Join(dir, "checksums.txt"), filepath.Join(dir, "app_Linux_x86_64.tar.gz"))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if want := wantPage(hashed); out != want {
		t.Errorf("page:\n%s\nwant:\n%s", out, want)
	}
	if !strings.Contains(strings.Join(gh.called("api"), " "), "-f target_commitish=abc123") {
		t.Errorf("the target commit was not passed: %v", gh.called("api"))
	}
}

func TestNoAssetsSaysSoAndWhatIsPublishedInstead(t *testing.T) {
	gh := &fakeGH{}
	code, out, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2", "-note", note)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if want := wantPage(noAssets + "\n\n" + note); out != want {
		t.Errorf("page:\n%s\nwant:\n%s", out, want)
	}
	if gh.called("release download") != nil {
		t.Error("downloaded from a release with no assets")
	}
}

func TestNoAssetsAndNoNoteIsTheSentenceAlone(t *testing.T) {
	got := checksumBody(nil, "  ")
	if got != noAssets {
		t.Errorf("got %q", got)
	}
}

func TestPublishEditsTheExistingReleaseAndReadsItBack(t *testing.T) {
	gh := &fakeGH{assets: []string{"checksums.txt", "app_Linux_x86_64.tar.gz"}}
	code, out, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2", "-publish")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if out != "" {
		t.Errorf("publish printed to stdout: %q", out)
	}
	edit := strings.Join(gh.called("release edit"), " ")
	if !strings.Contains(edit, "--title app 0.0.2") || !strings.HasSuffix(edit, "-R o/r") {
		t.Errorf("edit call: %s", edit)
	}
	if strings.Contains(edit, "--latest") {
		t.Errorf("a main release must let GitHub decide latest: %s", edit)
	}
	if want := "app 0.0.2\n" + strings.TrimSpace(wantPage(hashed)); gh.published != want {
		t.Errorf("published:\n%s", gh.published)
	}
}

func TestPublishCreatesANestedModuleReleaseNotLatest(t *testing.T) {
	gh := &fakeGH{noRelease: true}
	tag := "integrations/mod/v0.0.2"
	code, _, errs := runPage(t, gh, "-name", "mod", "-tag", tag, "-previous", "integrations/mod/v0.0.1", "-latest=false", "-publish")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	create := strings.Join(gh.called("release create"), " ")
	for _, want := range []string{"release create " + tag + " --verify-tag", "--title mod 0.0.2", "--latest=false"} {
		if !strings.Contains(create, want) {
			t.Errorf("create call %q lacks %q", create, want)
		}
	}
	if !strings.Contains(strings.Join(gh.called("api"), " "), "-f previous_tag_name=integrations/mod/v0.0.1") {
		t.Errorf("previous tag not passed: %v", gh.called("api"))
	}
}

func TestAPublishedPageThatDiffersFails(t *testing.T) {
	gh := &fakeGH{tamper: true}
	code, _, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2", "-publish")
	if code != 1 || !strings.Contains(errs, "is not the composed one") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestGhFailuresAreReported(t *testing.T) {
	cases := map[string]string{
		"generate-notes":   "generate-notes for v0.0.2",
		"release download": "download the assets of v0.0.2",
		"release edit":     "publish v0.0.2",
		"name,body":        "read back v0.0.2",
	}
	for failOn, want := range cases {
		gh := &fakeGH{assets: []string{"checksums.txt"}, failOn: failOn}
		code, _, errs := runPage(t, gh, "-name", "app", "-tag", "v0.0.2", "-publish")
		if code != 1 || !strings.Contains(errs, want) {
			t.Errorf("%s: exit %d, stderr %q", failOn, code, errs)
		}
	}
}

func TestBadInputsFail(t *testing.T) {
	dir := fixtures(t)
	noHeading := filepath.Join(dir, "h.md")
	if err := os.WriteFile(noHeading, []byte("## Changes\n* x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-tag", "v1"}, 2, "-tag and -name are required"},
		{[]string{"-bogus"}, 2, "flag provided but not defined"},
		{[]string{"-name", "a", "-tag", "v1", "-highlights", filepath.Join(dir, "none.md")}, 1, "none.md"},
		{[]string{"-name", "a", "-tag", "v1", "-highlights", noHeading}, 1, "no \"## Highlights ⭐️\" heading"},
		{[]string{"-name", "a", "-tag", "v1", filepath.Join(dir, "missing.tar.gz")}, 1, "missing.tar.gz"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		args := []string{"-repo", "o/r"}
		if !strings.Contains(strings.Join(c.args, " "), "-highlights") {
			args = append(args, "-highlights", filepath.Join(dir, "highlights.md"))
		}
		args = append(args, c.args...)
		code := run(args, &fakeGH{noRelease: true}, &out, &errb)
		if code != c.code || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, errb.String())
		}
	}
}

func TestGeneratedNotesWithoutFullChangelogFail(t *testing.T) {
	_, err := compose(highlightsMD, "## What's Changed\n* x\n", nil, "")
	if err == nil || !strings.Contains(err.Error(), "Full Changelog") {
		t.Errorf("err = %v", err)
	}
}

func TestAHeadingMidLineIsNotTheHighlights(t *testing.T) {
	if _, err := compose("see ## Highlights ⭐️ below", "**Full Changelog**: x", nil, ""); err == nil {
		t.Error("accepted a heading that does not start a line")
	}
}

func TestGeneratedNotesWithOnlyTheChangelogLine(t *testing.T) {
	gh := &fakeGH{generated: "**Full Changelog**: https://github.com/o/r/commits/v0.0.1\r\n"}
	_, got, _ := runPage(t, gh, "-name", "app", "-tag", "v0.0.1")
	want := "## Highlights ⭐️\n\n* **One thing**: It changed for the user.\n* **Another thing**: So did this.\n\n" +
		"## Checksums\n\n" + noAssets + "\n\n**Full Changelog**: https://github.com/o/r/commits/v0.0.1\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDefaultsWithoutARepository(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	var errb bytes.Buffer
	o, err := parse([]string{"-name", "app", "-tag", "v0.0.2"}, &errb)
	if err != nil {
		t.Fatal(err)
	}
	if o.highlights != filepath.Join("docs", "releases", "v0.0.2.md") {
		t.Errorf("highlights default %q", o.highlights)
	}
	if got := strings.Join(notesArgs(o), " "); !strings.Contains(got, "repos/{owner}/{repo}/releases/generate-notes") {
		t.Errorf("notes args %s", got)
	}
	if got := withRepo(o, "release", "view"); len(got) != 2 {
		t.Errorf("-R added without a repository: %v", got)
	}
}
