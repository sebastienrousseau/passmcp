// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// root is the repository root, from this package's directory.
const root = "../.."

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func repoExists(p string) bool {
	_, err := os.Stat(filepath.Join(root, p))
	return err == nil
}

// AC: CRA-01
func TestSecurityPolicyStatesChannelAcknowledgementAndCRATimeline(t *testing.T) {
	policy := read(t, "SECURITY.md")
	if p := CheckSecurityPolicy(policy); len(p) != 0 {
		t.Fatalf("SECURITY.md fails its own check: %v", p)
	}
	// Removing each required statement in turn must fail the check, and
	// the problem must name what went missing.
	cuts := map[string]string{
		"security/advisories/new":           "report channel",
		"within **72 hours**":               "acknowledgement time",
		"**early warning within 24 hours**": "early warning",
		"**notification within 72 hours**":  "notification",
		"**final report within 14 days**":   "final report",
	}
	for cut, want := range cuts {
		if !strings.Contains(policy, cut) {
			t.Fatalf("fixture drifted: SECURITY.md no longer contains %q", cut)
		}
		broken := strings.ReplaceAll(policy, cut, "")
		p := CheckSecurityPolicy(broken)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), want) {
			t.Errorf("removing %q: got %v, want a problem naming %q", cut, p, want)
		}
	}
	if p := CheckSecurityPolicy(regexp.MustCompile(`(?i)actively\s+exploited`).ReplaceAllString(policy, "")); len(p) == 0 {
		t.Error("a policy that never says 'actively exploited' passed")
	}
	if p := CheckSecurityPolicy(""); len(p) != len(securityRequirements) {
		t.Errorf("an empty policy: got %d problems, want %d", len(p), len(securityRequirements))
	}
}

// AC: CRA-01
func TestSecurityPolicyAcceptsAnEmailChannelAndWrappedLines(t *testing.T) {
	policy := `Write to <mailto:security@example.com>. We acknowledge
reports within 72 hours. For an actively exploited vulnerability we send an
early warning within 24 hours, a notification within
72 hours and a final report within 14 days.`
	if p := CheckSecurityPolicy(policy); len(p) != 0 {
		t.Fatalf("got %v", p)
	}
}

// v008 is passmcp v0.0.8's published asset list, before the packages had
// SBOMs of their own.
var v008 = []string{
	"checksums.txt", "checksums.txt.intoto.jsonl", "checksums.txt.sigstore.json",
	"passmcp_0.0.8_linux_amd64.deb", "passmcp_0.0.8_linux_amd64.rpm",
	"passmcp_0.0.8_linux_arm64.deb", "passmcp_0.0.8_linux_arm64.rpm",
	"passmcp_Darwin_arm64.tar.gz", "passmcp_Darwin_arm64.tar.gz.cdx.sbom.json",
	"passmcp_Linux_x86_64.tar.gz", "passmcp_Linux_x86_64.tar.gz.cdx.sbom.json",
	"passmcp_Windows_x86_64.zip", "passmcp_Windows_x86_64.zip.cdx.sbom.json",
}

// AC: CRA-02
func TestReleaseAuditFailsWithoutAnSBOMPerArtefactOrProvenance(t *testing.T) {
	p := CheckReleaseAssets(v008)
	if len(p) != 4 {
		t.Fatalf("v0.0.8's four packages lack SBOMs: got %d problems: %v", len(p), p)
	}
	for _, pkg := range []string{"linux_amd64.deb", "linux_amd64.rpm", "linux_arm64.deb", "linux_arm64.rpm"} {
		if !strings.Contains(strings.Join(p, "\n"), pkg+" has no CycloneDX SBOM") {
			t.Errorf("no problem names %s", pkg)
		}
	}

	complete := append([]string{}, v008...)
	for _, a := range v008 {
		if strings.HasSuffix(a, ".deb") || strings.HasSuffix(a, ".rpm") {
			complete = append(complete, a+SBOMSuffix)
		}
	}
	if p := CheckReleaseAssets(complete); len(p) != 0 {
		t.Fatalf("a complete release fails the audit: %v", p)
	}

	var noProvenance []string
	for _, a := range complete {
		if !strings.HasSuffix(a, ProvenanceSuffix) {
			noProvenance = append(noProvenance, a)
		}
	}
	if p := CheckReleaseAssets(noProvenance); len(p) != 1 || !strings.Contains(p[0], "provenance") {
		t.Fatalf("a release without provenance: got %v", p)
	}
	if p := CheckReleaseAssets([]string{"checksums.txt", "x.intoto.jsonl"}); len(p) != 1 || !strings.Contains(p[0], "no installable artefact") {
		t.Fatalf("a release with nothing to audit passed: %v", p)
	}
}

// AC: CRA-02
func TestReleaseConfigProducesAnSBOMForEveryArtefactKind(t *testing.T) {
	cfg := read(t, ".goreleaser.yaml")
	for _, kind := range []string{"artifacts: archive", "artifacts: package"} {
		if !strings.Contains(cfg, kind) {
			t.Errorf(".goreleaser.yaml has no SBOM for %q", kind)
		}
	}
	wf := read(t, ".github/workflows/release.yml")
	for _, step := range []string{"actions/attest-build-provenance", "checksums.txt.intoto.jsonl", "scripts/cra/main.go release-assets"} {
		if !strings.Contains(wf, step) {
			t.Errorf("the release workflow no longer contains %q", step)
		}
	}
}

// AC: CRA-03
func TestCRAPageLinksEveryClaimToEvidenceThatExists(t *testing.T) {
	page := "docs/compliance/cra.md"
	md := read(t, page)
	if p := CheckClaims(md, page, repoExists); len(p) != 0 {
		t.Fatalf("%s has unsupported claims: %v", page, p)
	}
	for _, must := range []string{"## Role", "## Support period and security updates", "Updates are delivered", "latest release is supported"} {
		if !strings.Contains(md, must) {
			t.Errorf("%s does not state %q", page, must)
		}
	}
}

// AC: CRA-03
func TestClaimsCheckerCatchesUnsupportedAndBrokenClaims(t *testing.T) {
	md := `# Page

Intro prose is not a claim.

- **Linked to a file that exists**: see [SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md).
- **Relative evidence**: [ADR 0006](../adr/0006-no-client-telemetry.md#decision).
- **External source only**: [the regulation](https://eur-lex.europa.eu/eli/reg/2024/2847/oj).
- **A directory**: [workflows](https://github.com/sebastienrousseau/passmcp/tree/main/.github/workflows/).
- **No evidence at all** for this
  claim, wrapped across lines.
- **A file that is gone**: [old](https://github.com/sebastienrousseau/passmcp/blob/main/docs/nope.md).
* **Relative and gone**: [x](missing.md).
- **Not a repository file link**: [issues](https://github.com/sebastienrousseau/passmcp/issues), [mail](mailto:a@b.c), [here](#role).
`
	p := CheckClaims(md, "docs/compliance/cra.md", repoExists)
	joined := strings.Join(p, "\n")
	if len(p) != 3 {
		t.Fatalf("got %d problems, want 3: %v", len(p), p)
	}
	for _, want := range []string{"links to no evidence: - **No evidence at all** for this claim, wrapped", "docs/nope.md does not exist", "docs/compliance/missing.md does not exist"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no problem contains %q in %v", want, p)
		}
	}
	long := "- " + strings.Repeat("claim ", 40)
	if got := CheckClaims(long, "x.md", repoExists); len(got) != 1 || !strings.HasSuffix(got[0], "…") {
		t.Errorf("a long claim is not truncated: %v", got)
	}
}

// govulncheck is a -format json stream with three vulnerabilities: one
// whose module is required but package not imported, one whose package is
// imported but no symbol reached, and one passmcp calls.
const govulncheck = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"progress":{"message":"Scanning your code..."}}
{"osv":{"id":"GO-2026-0001","aliases":["CVE-2026-1111","GHSA-2345-6789-cfgh"]}}
{"osv":{"id":"GO-2026-0002","aliases":["CVE-2026-2222"]}}
{"osv":{"id":"GO-2026-0003"}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/a","version":"v1.2.0"}]}}
{"finding":{"osv":"GO-2026-0002","trace":[{"module":"example.com/b","version":"v0.9.0","package":"example.com/b/p"}]}}
{"finding":{"osv":"GO-2026-0002","trace":[{"module":"example.com/b","version":"v0.9.0"}]}}
{"finding":{"osv":"GO-2026-0003","fixed_version":"v2.0.1","trace":[{"module":"example.com/c","version":"v2.0.0","package":"example.com/c","function":"Parse"},{"module":"satellion.com/passmcp","package":"satellion.com/passmcp/cmd","function":"run"}]}}
`

// AC: CRA-04
func TestVEXSaysNotAffectedWithTheReasonForUnreachedDependencies(t *testing.T) {
	at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	const product = "pkg:golang/satellion.com/passmcp@v0.0.9"
	doc, err := BuildVEX(strings.NewReader(govulncheck), product, "maintainer", at)
	if err != nil {
		t.Fatal(err)
	}
	if p := ValidateVEX(doc); len(p) != 0 {
		t.Fatalf("the generated document is invalid: %v", p)
	}
	if len(doc.Statements) != 3 || doc.NotAffected() != 2 {
		t.Fatalf("got %d statements, %d not affected; want 3 and 2", len(doc.Statements), doc.NotAffected())
	}
	want := []struct{ id, status, just, component string }{
		{"GO-2026-0001", StatusNotAffected, JustificationNotPresent, "pkg:golang/example.com/a@v1.2.0"},
		{"GO-2026-0002", StatusNotAffected, JustificationNotInPath, "pkg:golang/example.com/b@v0.9.0"},
		{"GO-2026-0003", StatusAffected, "", "pkg:golang/example.com/c@v2.0.0"},
	}
	for i, w := range want {
		s := doc.Statements[i]
		if s.Vulnerability.Name != w.id || s.Status != w.status || s.Justification != w.just {
			t.Errorf("statement %d: got %s %s %s, want %s %s %s", i, s.Vulnerability.Name, s.Status, s.Justification, w.id, w.status, w.just)
		}
		if s.Products[0].ID != product || s.Products[0].Subcomponents[0].ID != w.component {
			t.Errorf("statement %d: products %+v", i, s.Products)
		}
	}
	if got := doc.Statements[0].Vulnerability.Aliases; len(got) != 2 || got[0] != "CVE-2026-1111" {
		t.Errorf("aliases not carried: %v", got)
	}
	if !strings.Contains(doc.Statements[2].ActionStatement, "v2.0.1") {
		t.Errorf("the affected statement does not name the fixed version: %q", doc.Statements[2].ActionStatement)
	}
	if doc.Timestamp != "2026-09-27T12:00:00Z" || doc.Context != OpenVEXContext {
		t.Errorf("header: %+v", doc)
	}
	// The document is valid JSON that round-trips.
	b, _ := json.Marshal(doc)
	var back VEX
	if err := json.Unmarshal(b, &back); err != nil || len(ValidateVEX(back)) != 0 {
		t.Fatalf("round trip: %v %v", err, ValidateVEX(back))
	}
}

// AC: CRA-04
func TestVEXValidationAndInputErrors(t *testing.T) {
	if _, err := BuildVEX(strings.NewReader("{not json"), "p", "a", time.Now()); err == nil {
		t.Fatal("malformed govulncheck output was accepted")
	}
	empty, err := BuildVEX(strings.NewReader(""), "p", "a", time.Now())
	if err != nil || len(empty.Statements) != 0 || empty.NotAffected() != 0 {
		t.Fatalf("no findings: %v %+v", err, empty)
	}
	bad := VEX{Context: "x", Timestamp: "yesterday", Statements: []Statement{
		{Status: "maybe"},
		{Vulnerability: Vulnerability{Name: "GO-1"}, Products: []Product{{ID: "p"}}, Status: StatusNotAffected},
		{Vulnerability: Vulnerability{Name: "GO-2"}, Products: []Product{{ID: "p"}}, Status: StatusAffected},
	}}
	p := strings.Join(ValidateVEX(bad), "\n")
	for _, want := range []string{"@context", "@id and author", "timestamp", "no vulnerability name", "no product", "unknown status maybe", "not_affected needs", "affected needs an action"} {
		if !strings.Contains(p, want) {
			t.Errorf("validation missed %q in:\n%s", want, p)
		}
	}
	if fixedOr("") == "" {
		t.Error("an unknown fixed version produced no wording")
	}
}

// AC: CRA-04
func TestReleaseNotesNameAdvisoriesAndAffectedVersions(t *testing.T) {
	good := `## Highlights ⭐️

* **Security fix: a redirect no longer carries the API key**: GHSA-4374-p667-p6c8 (CVE-2026-1234). Affected versions: v0.0.3 to v0.0.8.
* **Faster reports**: rendering allocates less.
`
	if p := CheckAdvisoryNotes(good); len(p) != 0 {
		t.Fatalf("good notes: %v", p)
	}
	if ids := AdvisoryIDs(good + " GHSA-4374-p667-p6c8 GO-2026-4001"); strings.Join(ids, ",") != "GHSA-4374-p667-p6c8,CVE-2026-1234,GO-2026-4001" {
		t.Errorf("advisory IDs: %v", ids)
	}
	noID := "* **Security fix: tokens leaked**: fixed. Affected versions: v0.0.8.\n"
	if p := CheckAdvisoryNotes(noID); len(p) != 1 || !strings.Contains(p[0], "no advisory ID") {
		t.Errorf("a security fix without an ID: %v", p)
	}
	noRange := "* **Security fix: tokens leaked**: GHSA-4374-p667-p6c8.\n* **Dependency bump**: fixes CVE-2026-9999.\n"
	if p := CheckAdvisoryNotes(noRange); len(p) != 2 {
		t.Errorf("advisories without affected versions: %v", p)
	}
	// Every release highlights file already in the repository passes.
	files, _ := filepath.Glob(filepath.Join(root, "docs/releases/v*.md"))
	if len(files) == 0 {
		t.Fatal("no release highlights files found")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if p := CheckAdvisoryNotes(string(b)); len(p) != 0 {
			t.Errorf("%s: %v", f, p)
		}
	}
	guide := read(t, "docs/releases/README.md")
	for _, must := range []string{"Security fix", "Affected versions:", "OpenVEX", "vulnerable_code_not_in_execute_path"} {
		if !strings.Contains(guide, must) {
			t.Errorf("docs/releases/README.md does not explain %q", must)
		}
	}
}

// AC: CRA-05
func TestSecurityTxtNeedsItsFieldsAndThirtyDaysBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	good := `# satellion.com
Contact: https://github.com/sebastienrousseau/passmcp/security/advisories/new
contact: mailto:sebastian.rousseau@gmail.com
Expires: 2027-09-27T00:00:00Z
Policy: https://github.com/sebastienrousseau/passmcp/security/policy
Canonical: https://satellion.com/.well-known/security.txt
Preferred-Languages: en
`
	if p := CheckSecurityTxt(good, now); len(p) != 0 {
		t.Fatalf("a valid file: %v", p)
	}
	soon := strings.Replace(good, "2027-09-27T00:00:00Z", "2026-10-20T00:00:00Z", 1)
	if p := CheckSecurityTxt(soon, now); len(p) != 1 || !strings.Contains(p[0], "less than 30 days") {
		t.Errorf("expiring in 23 days: %v", p)
	}
	if p := CheckSecurityTxt(soon, now.Add(-10*24*time.Hour)); len(p) != 0 {
		t.Errorf("33 days of headroom failed: %v", p)
	}
	cases := map[string]string{
		"no Contact":        "Contact",
		"no Policy":         "Policy",
		"no Canonical":      "Canonical",
		"Expires: tomorrow": "not an RFC 3339 date",
		"two Expires":       "exactly one Expires",
		"no Expires":        "exactly one Expires",
	}
	for name, want := range cases {
		text := good
		switch name {
		case "no Contact":
			text = strings.NewReplacer("Contact:", "X:", "contact:", "X:").Replace(text)
		case "no Policy":
			text = strings.Replace(text, "Policy:", "X:", 1)
		case "no Canonical":
			text = strings.Replace(text, "Canonical:", "X:", 1)
		case "Expires: tomorrow":
			text = strings.Replace(text, "2027-09-27T00:00:00Z", "tomorrow", 1)
		case "two Expires":
			text += "Expires: 2027-01-01T00:00:00Z\n"
		case "no Expires":
			text = strings.Replace(text, "Expires:", "X:", 1)
		}
		if p := strings.Join(CheckSecurityTxt(text+"not a field line\n", now), "\n"); !strings.Contains(p, want) {
			t.Errorf("%s: got %q, want it to mention %q", name, p, want)
		}
	}
}
