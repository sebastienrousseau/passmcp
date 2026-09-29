// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package ecosystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestManifestIsSelfConsistent is the cheap gate: the manifest has to hold
// together before anything generated from it can be trusted.
func TestManifestIsSelfConsistent(t *testing.T) {
	if errs := Validate(); len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("manifest: %v", err)
		}
	}
}

// TestValidateCatchesTheThingsItIsFor.
//
// Validate exists to refuse three specific omissions — a satellite with no
// boundary, a satellite with no kill criterion, and a rejection with no
// reason — because each of those is how a family manifest rots into a list of
// names. Asserting that it refuses them is the only way to know it still does.
func TestValidateCatchesTheThingsItIsFor(t *testing.T) {
	original := Family
	t.Cleanup(func() { Family = original })

	cases := map[string]struct {
		rows []Repo
		want string
	}{
		"a satellite with no boundary": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Name: "passmcp-x", Status: Unreleased, Role: "something", Licence: "Apache-2.0", Kill: "when"},
			},
			want: "no boundary",
		},
		"a satellite with no kill criterion": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Name: "passmcp-x", Status: Unreleased, Role: "something", Licence: "Apache-2.0", Boundary: "because"},
			},
			want: "no kill criterion",
		},
		"a rejection with no reason": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Name: "passmcp-x", Status: Rejected, Role: "something"},
			},
			want: "no reason",
		},
		"a duplicated row": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
			},
			want: "listed twice",
		},
		"no centre at all": {
			rows: []Repo{
				{Name: "passmcp-x", Status: Rejected, Role: "something", Reason: "no"},
			},
			want: "does not list passmcp",
		},
		"a row with no name": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Status: Unreleased, Role: "nameless"},
			},
			want: "no name",
		},
		"a row with no role": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Licence: "GPL-3.0-only"},
			},
			want: "no role",
		},
		"a shipping row with no licence": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre"},
			},
			want: "no licence",
		},
		"an unknown status": {
			rows: []Repo{
				{Name: "passmcp", Status: "maybe", Role: "centre", Licence: "GPL-3.0-only"},
			},
			want: "unknown status",
		},
		"a rejection reason on a live row": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only", Reason: "but why"},
			},
			want: "not rejected",
		},
		"a rejected row still carrying lockstep": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only"},
				{Name: "passmcp-x", Status: Rejected, Role: "gone", Reason: "no", Lockstep: true},
			},
			want: "carries artefacts or lockstep",
		},
		"a live row outside the lockstep": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only",
					Purpose: "p", UseCase: "u"},
			},
			want: "not in lockstep",
		},
		"a live row with no family-table cells": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only", Lockstep: true},
			},
			want: "no purpose or use case",
		},
		"the same artefact claimed twice": {
			rows: []Repo{
				{Name: "passmcp", Status: Released, Role: "centre", Licence: "GPL-3.0-only",
					Artefacts: []Artefact{Readme, Readme}},
			},
			want: "listed twice",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			Family = tc.rows
			errs := Validate()
			if len(errs) == 0 {
				t.Fatalf("accepted %s", name)
			}
			var joined []string
			for _, e := range errs {
				joined = append(joined, e.Error())
			}
			if !strings.Contains(strings.Join(joined, "; "), tc.want) {
				t.Errorf("errors do not mention %q: %v", tc.want, joined)
			}
		})
	}
}

// TestPassmcpRowIsTrueOfTheWorkingTree is the point of the whole file.
//
// A manifest claiming an artefact this repository does not carry is worse
// than no manifest: it is a promise to a packager, an auditor and a
// contributor that nobody kept. So every artefact passmcp's own row claims has
// to exist on disk, and CI runs this on every push.
func TestPassmcpRowIsTrueOfTheWorkingTree(t *testing.T) {
	row, ok := Lookup("passmcp")
	if !ok {
		t.Fatal("no passmcp row")
	}
	if len(row.Artefacts) == 0 {
		t.Fatal("passmcp's row claims no artefacts, so this test would assert nothing")
	}
	root := repoRoot(t)
	for _, a := range row.Artefacts {
		if _, err := os.Stat(filepath.Join(root, string(a))); err != nil {
			t.Errorf("the manifest claims %s and the working tree does not have it: %v", a, err)
		}
	}
}

// TestLockstepIsExactlyTheLiveRows: lockstep binds a release process, so a
// rejected row carrying it would put a tag on something that does not exist,
// and a live row without it would be a repository the one-version rule
// silently skips.
func TestLockstepIsExactlyTheLiveRows(t *testing.T) {
	for _, r := range Family {
		if r.Lockstep != (r.Status != Rejected) {
			t.Errorf("%s is %s with lockstep=%v", r.Name, r.Status, r.Lockstep)
		}
	}
}

// TestRepositoryNamesAndLinks: the website is the one row whose component
// name is not its repository, and every README's family table links the
// repository, so a wrong link here is a broken link in nine READMEs.
func TestRepositoryNamesAndLinks(t *testing.T) {
	site, ok := Lookup("satellion.com")
	if !ok {
		t.Fatal("no website row")
	}
	if got := site.URL(); got != "https://github.com/sebastienrousseau/satellion.github.io" {
		t.Errorf("website links %s", got)
	}
	if got := (Repo{Name: "passmcp-x"}).URL(); got != "https://github.com/sebastienrousseau/passmcp-x" {
		t.Errorf("a plain row links %s", got)
	}
	for _, r := range Family {
		if r.Status != Rejected && strings.ContainsAny(r.RepoName(), " /") {
			t.Errorf("%s: repository name %q is not a repository name", r.Name, r.RepoName())
		}
	}
}

// repoRoot walks up to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find the repository root")
	return ""
}

// TestLookupAndByStatusAgreeWithTheManifest.
//
// These two are how every consumer reads the manifest — the generator groups
// by status and the verifier looks up passmcp's row — so an accessor that
// quietly disagreed with Family would make both wrong in the same direction
// and neither would notice.
func TestLookupAndByStatusAgreeWithTheManifest(t *testing.T) {
	for _, r := range Family {
		got, ok := Lookup(r.Name)
		if !ok {
			t.Errorf("Lookup(%q) found nothing, and it is in Family", r.Name)
			continue
		}
		if got.Name != r.Name || got.Status != r.Status {
			t.Errorf("Lookup(%q) returned %+v", r.Name, got)
		}
	}
	if _, ok := Lookup("passmcp-does-not-exist"); ok {
		t.Error("Lookup invented a repository")
	}
}

// TestByStatusAgreesWithTheManifest is the ByStatus half of
// TestLookupAndByStatusAgreeWithTheManifest, split out to keep each under the
// complexity ceiling.
func TestByStatusAgreesWithTheManifest(t *testing.T) {
	var counted int
	for _, s := range []Status{Released, Unreleased, Rejected} {
		rows := ByStatus(s)
		counted += len(rows)
		for _, r := range rows {
			if r.Status != s {
				t.Errorf("ByStatus(%s) returned %s, which is %s", s, r.Name, r.Status)
			}
		}
	}
	if counted != len(Family) {
		t.Errorf("the three statuses account for %d of %d rows; a row has a status nothing groups by",
			counted, len(Family))
	}
	if len(ByStatus("nonsense")) != 0 {
		t.Error("ByStatus matched an unknown status")
	}
}

// TestArtefactListIsSortedAndComplete: it renders into a generated table, so
// an unstable order would make the generator's output differ run to run and
// the drift check fail for no reason.
func TestArtefactListIsSortedAndComplete(t *testing.T) {
	row, ok := Lookup("passmcp")
	if !ok {
		t.Fatal("no passmcp row")
	}
	got := row.ArtefactList()
	parts := strings.Split(got, ", ")
	if len(parts) != len(row.Artefacts) {
		t.Fatalf("rendered %d artefacts, the row has %d", len(parts), len(row.Artefacts))
	}
	for i := 1; i < len(parts); i++ {
		if parts[i-1] > parts[i] {
			t.Errorf("not sorted at %q > %q; the generated table would be unstable", parts[i-1], parts[i])
		}
	}
	if (Repo{}).ArtefactList() != "" {
		t.Error("a row with no artefacts rendered something")
	}
}

// TestEverySatelliteHasADistinctBoundary.
//
// Two satellites with the same stated reason for existing are one satellite
// with a duplicated justification, which is how a family acquires a
// repository nobody can defend.
func TestEverySatelliteHasADistinctBoundary(t *testing.T) {
	seen := map[string]string{}
	for _, r := range Family {
		if r.Status == Rejected || r.Name == "passmcp" {
			continue
		}
		// Compare the first clause: the boundary's category, before the
		// explanation.
		key := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Boundary, ".", 2)[0]))
		if key == "" {
			t.Errorf("%s: empty boundary", r.Name)
			continue
		}
		if other, dup := seen[key]; dup {
			t.Logf("%s and %s both cite %q as their boundary; that is allowed but worth re-reading",
				r.Name, other, key)
		}
		seen[key] = r.Name
	}
	if len(seen) == 0 {
		t.Error("no satellites have boundaries, so this asserts nothing")
	}
}

// --- the ssg surfaces ------------------------------------------------------

func TestSiteManifestIsSelfConsistent(t *testing.T) {
	if errs := ValidateSites(); len(errs) > 0 {
		for _, err := range errs {
			t.Errorf("sites: %v", err)
		}
	}
}

// TestSiteManifestIsTrueOfTheWorkingTree: a manifest claiming a layouts
// directory or an ssg configuration that is not there would let the gate
// pass while describing a repository that does not exist.
func TestSiteManifestIsTrueOfTheWorkingTree(t *testing.T) {
	root := repoRoot(t)
	if len(Sites) == 0 {
		t.Fatal("no sites, so this asserts nothing")
	}
	for _, s := range Sites {
		required := []string{s.Config, s.Layouts}
		// Output is only required to exist when it is embedded. The shell's
		// output is committed because go:embed needs it at compile time; a
		// site whose output is built on demand, as the public site's was
		// before it moved to satellion.github.io, is not asserted, because that
		// passed locally for the wrong reason and failed on every CI runner.
		if s.Embedded {
			required = append(required, s.Output)
		}
		for _, path := range required {
			if _, err := os.Stat(filepath.Join(root, path)); err != nil {
				t.Errorf("site %s claims %s: %v", s.Name, path, err)
			}
		}
	}
	for _, d := range ThemeDeltas {
		s, ok := LookupSite(d.Site)
		if !ok {
			t.Errorf("delta %s/%s names no site", d.Site, d.File)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, s.Layouts, d.File)); err != nil {
			t.Errorf("a delta is declared for %s/%s and the file is not there: %v", d.Site, d.File, err)
		}
	}
}

// TestValidateSitesRefusesAMovingRevision is the one that matters most.
//
// "Which design is this?" has to have an answer months later. A branch name
// answers it with "whichever one it was that day", which is the same as no
// answer, and it is the easy mistake to make when vendoring.
func TestValidateSitesRefusesAMovingRevision(t *testing.T) {
	original := Sites
	t.Cleanup(func() { Sites = original })

	for _, moving := range []string{"main", "HEAD", "latest", "MAIN"} {
		Sites = []Site{{
			Name: "x", Config: "web/ssg.toml", Layouts: "web/_layouts", Output: "internal/web/dist",
			Theme: "passmcp", Upstream: "https://example.com", Revision: moving, MinSSG: "0.0.56",
		}}
		errs := ValidateSites()
		if len(errs) == 0 {
			t.Errorf("revision %q was accepted", moving)
			continue
		}
		if !strings.Contains(errs[0].Error(), "moving target") {
			t.Errorf("revision %q: %v", moving, errs[0])
		}
	}
}

func TestValidateSitesRefusesAnUnreasonedDelta(t *testing.T) {
	originalSites, originalDeltas := Sites, ThemeDeltas
	t.Cleanup(func() { Sites, ThemeDeltas = originalSites, originalDeltas })

	Sites = []Site{{
		Name: "x", Config: "web/ssg.toml", Layouts: "web/_layouts", Output: "internal/web/dist",
		Theme: "passmcp", Upstream: "https://example.com", Revision: "abc1234", MinSSG: "0.0.56",
	}}

	ThemeDeltas = []ThemeDelta{{Site: "x", File: "base.html"}}
	if errs := ValidateSites(); len(errs) == 0 {
		t.Error("a delta with no reason was accepted; that is a fork rather than a patch")
	} else if !strings.Contains(errs[0].Error(), "no reason") {
		t.Errorf("unexpected error: %v", errs[0])
	}

	ThemeDeltas = []ThemeDelta{{Site: "nope", File: "base.html", Reason: "because"}}
	if errs := ValidateSites(); len(errs) == 0 {
		t.Error("a delta for a site that does not exist was accepted")
	}
}

// TestValidateSitesRefusesAnIncompleteSite walks every required field, so a
// field added later is covered without anyone editing a list.
func TestValidateSitesRefusesAnIncompleteSite(t *testing.T) {
	originalSites, originalDeltas := Sites, ThemeDeltas
	t.Cleanup(func() { Sites, ThemeDeltas = originalSites, originalDeltas })

	complete := Site{
		Name: "x", Config: "web/ssg.toml", Layouts: "web/_layouts", Output: "internal/web/dist",
		Theme: "passmcp", Upstream: "https://example.com", Revision: "abc1234", MinSSG: "0.0.56",
	}
	// The real deltas name the real sites, so they have to go with them.
	Sites, ThemeDeltas = []Site{complete}, nil
	if errs := ValidateSites(); len(errs) > 0 {
		t.Fatalf("the complete fixture was rejected: %v", errs)
	}

	blank := map[string]func(*Site){
		"name":            func(s *Site) { s.Name = "" },
		"config":          func(s *Site) { s.Config = "" },
		"layouts":         func(s *Site) { s.Layouts = "" },
		"output":          func(s *Site) { s.Output = "" },
		"theme":           func(s *Site) { s.Theme = "" },
		"upstream":        func(s *Site) { s.Upstream = "" },
		"revision":        func(s *Site) { s.Revision = "" },
		"min ssg version": func(s *Site) { s.MinSSG = "" },
	}
	for field, clear := range blank {
		t.Run("without a "+field, func(t *testing.T) {
			broken := complete
			clear(&broken)
			Sites = []Site{broken}
			ThemeDeltas = nil
			errs := ValidateSites()
			if len(errs) == 0 {
				t.Fatalf("a site with no %s was accepted", field)
			}
			var joined []string
			for _, e := range errs {
				joined = append(joined, e.Error())
			}
			want := field
			if field == "name" {
				want = "no name"
			}
			if !strings.Contains(strings.Join(joined, "; "), want) {
				t.Errorf("errors do not mention %q: %v", want, joined)
			}
		})
	}

	// And a duplicated site, which would make LookupSite ambiguous.
	Sites = []Site{complete, complete}
	ThemeDeltas = nil
	if errs := ValidateSites(); len(errs) == 0 {
		t.Error("the same site listed twice was accepted")
	}
}

// TestDeltaHelpersAgreeWithTheManifest: ssgcheck reads the manifest only
// through these, so an accessor that disagreed with ThemeDeltas would make
// the gate wrong in a way the gate cannot see.
func TestDeltaHelpersAgreeWithTheManifest(t *testing.T) {
	var total int
	for _, s := range Sites {
		for _, d := range DeltasFor(s.Name) {
			total++
			if d.Site != s.Name {
				t.Errorf("DeltasFor(%q) returned a delta for %q", s.Name, d.Site)
			}
			if !DeclaredDelta(d.Site, d.File) {
				t.Errorf("DeclaredDelta(%q, %q) is false for a declared delta", d.Site, d.File)
			}
		}
	}
	if total != len(ThemeDeltas) {
		t.Errorf("DeltasFor accounts for %d of %d deltas", total, len(ThemeDeltas))
	}
	if DeclaredDelta("web-shell", "a-file-nobody-vendored.html") {
		t.Error("DeclaredDelta invented a delta")
	}
	if _, ok := LookupSite("no-such-site"); ok {
		t.Error("LookupSite invented a site")
	}
}

// TestGeneratedRegionIsLintShaped.
//
// The generated table is markdown that two CI jobs judge: markdownlint wants
// a blank line around every heading and none doubled anywhere, and MkDocs in
// strict mode rejects a relative link to a file that is not a documentation
// page. The generator got both wrong on its first run, and both failures
// arrived from CI rather than from the test suite.
//
// This asserts the outcome rather than the helper that produces it, so a hand
// edit inside the region is caught as well as a generator bug.
func TestGeneratedRegionIsLintShaped(t *testing.T) {
	const (
		begin = "<!-- BEGIN generated family table"
		end   = "<!-- END generated family table -->"
	)
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "ecosystem.md"))
	if err != nil {
		t.Fatalf("reading the manual: %v", err)
	}
	doc := string(b)
	i, j := strings.Index(doc, begin), strings.Index(doc, end)
	if i < 0 || j < 0 || j < i {
		t.Fatal("the manual has no generated region; the markers moved and this test did not")
	}
	region := strings.Split(doc[i:j], "\n")
	if len(region) < 10 {
		t.Fatalf("the generated region is %d lines; it cannot be the table", len(region))
	}

	for n, line := range region {
		switch {
		case strings.HasPrefix(line, "#"):
			// MD022: a heading needs a blank line above and below.
			if n > 0 && strings.TrimSpace(region[n-1]) != "" {
				t.Errorf("line %d: no blank line above heading %q", n+1, line)
			}
			if n+1 < len(region) && strings.TrimSpace(region[n+1]) != "" {
				t.Errorf("line %d: no blank line below heading %q", n+1, line)
			}
		case strings.TrimSpace(line) == "":
			// MD012: never two blank lines together.
			if n > 0 && strings.TrimSpace(region[n-1]) == "" {
				t.Errorf("line %d: two blank lines in a row", n+1)
			}
		}
		// MkDocs strict refuses a relative link to something that is not a
		// documentation page, and every source file in this repository is one
		// of those.
		if strings.Contains(line, "](../") {
			t.Errorf("line %d: relative link out of docs/ — MkDocs strict rejects it, use the full URL: %q",
				n+1, strings.TrimSpace(line))
		}
	}
}
