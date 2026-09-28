// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are written in the shape each tool writes, with digests
// that decode to the right length, because a reader that only ever saw
// tidy input is a reader that has not been tested.

const (
	sdkSRI = "sha512-h2on+Jc0qLYIZcPraOg4W84jLsxJWRhwUVDj4eBGjxF14EeXhXBSI4EsWkrp5FpEodGLSHdZ/un1rRQeYV/lIA=="
	sdkHex = "876a27f89734a8b60865c3eb68e8385bce232ecc495918705150e3e1e0468f1175e0479785705223812c5a4ae9e45a44a1d18b487759fee9f5ad141e615fe520"
	zodSRI = "sha512-+VVcLfvhYjIfHVeV3UM7uVJDMKk2bi0J/QS6ZmVCQWf+PMX92YkMm6GrnNGt32Sk7ajNYJFruhwnTfNddtClEQ=="
	tsSRI  = "sha512-D2SrX2+VHid3WW5a0OWuAMHtNcWvmwC9E+3F2PY272zK4+nsKcOHXOwFkw1vZ6VhhLpqNgCc7+LkwSAUvTh8ow=="

	serdeHex = "8b917c4b6163bc82ef4aff025c6f5f4d54205232c4595f39b7b43008256a6cb7"
	anyioHex = "d07ebf7465b4aa3ee99060bc5b1347bd3a913a761c1534fdba3b8f844fd80a68"
	wheelHex = "e9bdb84714b70cbcbbcc8309f202669f8344005013b9ff504a5847e40b1619a8"
	httpxHex = "44c3f6f83c39094fec0db8b7f158d0a8fad3418e77f5f739b103e1ac73eee5d8"
)

const npmV3 = `{
  "name": "mcp-weather",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "mcp-weather", "version": "1.0.0", "workspaces": ["packages/w"] },
    "node_modules/@modelcontextprotocol/sdk": {
      "version": "1.20.0",
      "resolved": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.20.0.tgz",
      "integrity": "` + sdkSRI + `"
    },
    "node_modules/zod": { "version": "3.23.8", "integrity": "` + zodSRI + `", "dev": true },
    "node_modules/@modelcontextprotocol/sdk/node_modules/zod": { "version": "3.23.8", "integrity": "` + zodSRI + `" },
    "node_modules/typescript": { "version": "5.6.2", "integrity": "` + tsSRI + `", "dev": true },
    "node_modules/local-thing": { "version": "0.0.1", "resolved": "file:../local-thing" },
    "node_modules/from-git": { "version": "2.0.0", "resolved": "git+ssh://git@github.com/o/r.git#abc" },
    "node_modules/bare": { "version": "1.0.0" },
    "node_modules/garbled": { "version": "1.0.0", "integrity": "sha512-notbase64!" },
    "node_modules/w": { "resolved": "packages/w", "link": true },
    "packages/w": { "name": "w", "version": "0.1.0" },
    "node_modules/aliased": { "name": "real-name", "version": "4.0.0", "integrity": "` + tsSRI + `" },
    "node_modules/npm": { "version": "10.9.0", "integrity": "` + sdkSRI + `" },
    "node_modules/npm/node_modules/semver": { "version": "7.6.3", "inBundle": true },
    "node_modules/npm/node_modules/ms": { "version": "2.1.3", "inBundle": true },
    "node_modules/ms": { "version": "2.1.3", "integrity": "` + zodSRI + `" }
  }
}`

// writeLock puts one lockfile in a fresh directory.
func writeLock(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func inspect(t *testing.T, files map[string]string) *Inventory {
	t.Helper()
	inv, err := InspectDir(writeLock(t, files))
	if err != nil {
		t.Fatalf("InspectDir: %v", err)
	}
	return inv
}

// byName indexes packages for assertions.
func byName(inv *Inventory) map[string]Package {
	out := map[string]Package{}
	for _, p := range inv.Packages {
		out[p.Name] = p
	}
	return out
}

func TestNPMLockReadsTheFlatPackagesMap(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": npmV3})

	if inv.Root == nil || inv.Root.Name != "mcp-weather" || inv.Root.Version != "1.0.0" {
		t.Fatalf("root = %+v", inv.Root)
	}
	pkgs := byName(inv)

	sdk := pkgs["@modelcontextprotocol/sdk"]
	if len(sdk.Hashes) != 1 || sdk.Hashes[0].Alg != "SHA-512" || sdk.Hashes[0].Content != sdkHex {
		t.Errorf("sdk hash = %+v, want SHA-512 %s", sdk.Hashes, sdkHex)
	}
	if got, want := sdk.purl(), "pkg:npm/%40modelcontextprotocol/sdk@1.20.0"; got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
	if !pkgs["typescript"].Dev {
		t.Error("typescript is a development dependency and was not marked")
	}
	if _, ok := pkgs["w"]; ok {
		t.Error("a workspace member was listed as a dependency")
	}
	if _, ok := pkgs["real-name"]; !ok {
		t.Error("an aliased install was not listed under its real name")
	}
}

// TestOneProductionCopyMakesItShip. zod is installed twice, once as a
// development dependency and once under a production one, which puts it
// in what ships.
func TestOneProductionCopyMakesItShip(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": npmV3})
	n := 0
	for _, p := range inv.Packages {
		if p.Name == "zod" {
			n++
			if p.Dev {
				t.Error("zod was marked development-only although a production package depends on it")
			}
		}
	}
	if n != 1 {
		t.Errorf("zod listed %d times, want once", n)
	}
}

func TestNPMSaysWhyAnEntryCannotBeVerified(t *testing.T) {
	pkgs := byName(inspect(t, map[string]string{"package-lock.json": npmV3}))
	for name, want := range map[string]string{
		"local-thing": "local path",
		"from-git":    "git URL",
		"bare":        "no integrity hash",
		"garbled":     "not a well-formed",
	} {
		if got := pkgs[name].Unverifiable; !strings.Contains(got, want) {
			t.Errorf("%s: unverifiable = %q, want it to mention %q", name, got, want)
		}
	}
	if pkgs["@modelcontextprotocol/sdk"].Unverifiable != "" {
		t.Error("a hashed package was marked unverifiable")
	}
}

// TestABundledPackageIsCoveredByItsParent. npm records no integrity for
// a bundled dependency because it is not downloaded separately; flagging
// it would put a false warning on every package that bundles, and a real
// lockfile had 128 of them.
func TestABundledPackageIsCoveredByItsParent(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": npmV3})
	pkgs := byName(inv)
	semver := pkgs["semver"]
	if semver.Unverifiable != "" || !semver.Bundled {
		t.Errorf("bundled semver: %+v", semver)
	}
	// ms is bundled once and installed with a hash once: the hash wins.
	ms := pkgs["ms"]
	if len(ms.Hashes) != 1 || ms.Bundled || ms.Unverifiable != "" {
		t.Errorf("ms: %+v, want the hashed copy", ms)
	}
	doc, _ := emitInventory(t, inv)
	for _, c := range doc.Components {
		if c.Name == "semver" && !hasProperty(c.Properties, "passmcp:bundled") {
			t.Error("the document does not say why semver has no hash")
		}
	}
}

func TestNPMLockVersionOneIsWalkedToTheLeaves(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": `{
  "name": "old", "version": "0.1.0", "lockfileVersion": 1,
  "dependencies": {
    "a": { "version": "1.0.0", "integrity": "` + zodSRI + `",
      "dependencies": { "b": { "version": "2.0.0", "integrity": "` + tsSRI + `", "dev": true } } }
  }
}`})
	pkgs := byName(inv)
	if len(pkgs) != 2 || pkgs["b"].Version != "2.0.0" || !pkgs["b"].Dev {
		t.Fatalf("packages = %+v", inv.Packages)
	}
}

func TestNPMRefusesSomethingThatIsNotALockfile(t *testing.T) {
	for _, body := range []string{`{}`, `[1,2]`, `not json`} {
		if _, err := InspectDir(writeLock(t, map[string]string{"package-lock.json": body})); err == nil {
			t.Errorf("%q was accepted as a lockfile", body)
		}
	}
}

const cargoLock = `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "mcp-rs"
version = "0.2.0"
dependencies = [
 "serde",
 "tokio",
]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "` + serdeHex + `"

[[package]]
name = "forked"
version = "0.1.0"
source = "git+https://github.com/o/forked?rev=abc#abcdef"

[[package]]
name = "short"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
`

func TestCargoLockReadsChecksumsAndTheRoot(t *testing.T) {
	inv := inspect(t, map[string]string{"Cargo.lock": cargoLock})
	if inv.Root == nil || inv.Root.Name != "mcp-rs" {
		t.Fatalf("root = %+v", inv.Root)
	}
	pkgs := byName(inv)
	if h := pkgs["serde"].Hashes; len(h) != 1 || h[0].Alg != "SHA-256" || h[0].Content != serdeHex {
		t.Errorf("serde hash = %+v", h)
	}
	if got := pkgs["serde"].purl(); got != "pkg:cargo/serde@1.0.210" {
		t.Errorf("purl = %q", got)
	}
	if !strings.Contains(pkgs["forked"].Unverifiable, "git") {
		t.Errorf("git dependency: %q", pkgs["forked"].Unverifiable)
	}
	if !strings.Contains(pkgs["short"].Unverifiable, "not a well-formed") {
		t.Errorf("short checksum: %q", pkgs["short"].Unverifiable)
	}
	if _, ok := pkgs["mcp-rs"]; ok {
		t.Error("the workspace's own package was listed as a dependency")
	}
}

// TestCargoFormatOneKeepsChecksumsInMetadata, which is where lockfiles
// older than Rust 1.41 put them.
func TestCargoFormatOneKeepsChecksumsInMetadata(t *testing.T) {
	inv := inspect(t, map[string]string{"Cargo.lock": `[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)" = "` + serdeHex + `"
`})
	if h := byName(inv)["serde"].Hashes; len(h) != 1 || h[0].Content != serdeHex {
		t.Errorf("format-1 checksum not found: %+v", inv.Packages)
	}
}

func TestCargoWorkspaceWithSeveralMembersListsThem(t *testing.T) {
	inv := inspect(t, map[string]string{"Cargo.lock": `[[package]]
name = "a"
version = "0.1.0"

[[package]]
name = "b"
version = "0.1.0"
`})
	if inv.Root != nil {
		t.Errorf("a two-member workspace was given a single root: %+v", inv.Root)
	}
	if len(inv.Packages) != 2 {
		t.Errorf("members = %+v", inv.Packages)
	}
}

func TestATruncatedTOMLArrayIsRefused(t *testing.T) {
	_, err := InspectDir(writeLock(t, map[string]string{"Cargo.lock": "[[package]]\nname = \"a\"\ndependencies = [\n \"b\",\n"}))
	if err == nil {
		t.Fatal("a lockfile ending inside an array was accepted")
	}
}

const uvLock = `version = 1
requires-python = ">=3.11"

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "sniffio", marker = "python_version < '3.12'" },
]
sdist = { url = "https://files.pythonhosted.org/anyio-4.4.0.tar.gz", hash = "sha256:` + anyioHex + `", size = 163930 }
wheels = [
    { url = "https://files.pythonhosted.org/anyio-4.4.0-py3-none-any.whl", hash = "sha256:` + wheelHex + `", size = 86780 },
]

[[package]]
name = "Wheel_Only"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://example/w.whl", hash = "sha256:` + wheelHex + `", size = 1 },
]

[[package]]
name = "from-git"
version = "0.3.0"
source = { git = "https://github.com/o/r?rev=main#abcdef" }

[[package]]
name = "mcp-server-fetch"
version = "0.6.2"
source = { editable = "." }
dependencies = [
    { name = "anyio" },
]

[package.optional-dependencies]
dev = [
    { name = "pytest" },
]

[manifest]
members = ["mcp-server-fetch"]
`

func TestUVLockTakesTheSdistHashAndTheEditableRoot(t *testing.T) {
	inv := inspect(t, map[string]string{"uv.lock": uvLock})
	if inv.Root == nil || inv.Root.Name != "mcp-server-fetch" {
		t.Fatalf("root = %+v", inv.Root)
	}
	pkgs := byName(inv)
	if h := pkgs["anyio"].Hashes; len(h) != 1 || h[0].Content != anyioHex {
		t.Errorf("anyio took %+v, want the sdist hash", h)
	}
	w := pkgs["Wheel_Only"]
	if len(w.Hashes) != 0 || w.Unverifiable != "" {
		t.Errorf("wheel-only package: %+v — it is pinned, with no single artifact to name", w)
	}
	if got := w.purl(); got != "pkg:pypi/wheel-only@1.0" {
		t.Errorf("purl = %q, want the PEP 503 name", got)
	}
	if !strings.Contains(pkgs["from-git"].Unverifiable, "git") {
		t.Errorf("git source: %q", pkgs["from-git"].Unverifiable)
	}
	if len(inv.Packages) != 3 {
		t.Errorf("packages = %d, want 3 (the optional-dependencies table is not a package)", len(inv.Packages))
	}
}

const requirements = `# pinned with hashes, as pip-compile --generate-hashes writes it
httpx==0.27.2 \
    --hash=sha256:` + httpxHex + `
anyio==4.4.0 --hash=sha256:` + anyioHex + ` --hash=sha256:` + wheelHex + `
pydantic[email]==2.9.2 ; python_version >= "3.11"
starlette>=0.38
-r other.txt
--index-url https://example.invalid/simple
-e .
git+https://github.com/o/r#egg=thing
typer===0.12.5  # arbitrary equality
`

func TestRequirementsSaysWhatWasLeftToTheIndex(t *testing.T) {
	inv := inspect(t, map[string]string{"requirements.txt": requirements})
	pkgs := byName(inv)
	if h := pkgs["httpx"].Hashes; len(h) != 1 || h[0].Content != httpxHex {
		t.Errorf("httpx across a continuation: %+v", pkgs["httpx"])
	}
	if a := pkgs["anyio"]; len(a.Hashes) != 0 || a.Unverifiable != "" {
		t.Errorf("anyio with two accepted hashes: %+v — pinned, with no single artifact", a)
	}
	if !strings.Contains(pkgs["pydantic"].Unverifiable, "without --hash") || pkgs["pydantic"].Version != "2.9.2" {
		t.Errorf("pydantic: %+v", pkgs["pydantic"])
	}
	if !strings.Contains(pkgs["starlette"].Unverifiable, "not pinned") {
		t.Errorf("starlette: %+v", pkgs["starlette"])
	}
	if pkgs["typer"].Version != "0.12.5" {
		t.Errorf("typer: %+v", pkgs["typer"])
	}
	if len(pkgs) != 5 {
		t.Errorf("packages = %v, want the five requirements and none of the options", inv.Packages)
	}
}

func TestEveryLockfilePresentIsRead(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": npmV3, "requirements.txt": "httpx==0.27.2\n"})
	if strings.Join(inv.Sources, ",") != "package-lock.json,requirements.txt" {
		t.Errorf("sources = %v", inv.Sources)
	}
	if byName(inv)["httpx"].Source != "requirements.txt" {
		t.Error("an entry does not name the lockfile it came from")
	}
	if got := inv.Unpinned(); len(got) == 0 || got[0] != "bare" {
		t.Errorf("Unpinned = %v", got)
	}
}

func TestADirectoryWithNoLockfileSaysWhatItLookedFor(t *testing.T) {
	_, err := InspectDir(t.TempDir())
	if !errors.Is(err, ErrNoManifest) || !strings.Contains(err.Error(), "uv.lock") {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectDirRefusesAFileAndAMissingPath(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDir(f); err == nil {
		t.Error("a file was accepted as a directory")
	}
	if _, err := InspectDir(filepath.Join(f, "nope")); err == nil {
		t.Error("a missing path was accepted")
	}
}

func TestAnOversizedLockfileIsRefusedNotTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: the size is what matters, not the bytes.
	if err := f.Truncate(maxLockfile + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := InspectDir(dir); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v", err)
	}
}

func TestAnUnreadableLockfileIsAnError(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: it exists, and reading it fails.
	if err := os.Mkdir(filepath.Join(dir, "uv.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDir(dir); err == nil {
		t.Fatal("an unreadable lockfile was skipped as if absent")
	}
}

func TestHashConversionsRefuseTheWrongLength(t *testing.T) {
	if got := sriHashes("sha512-AAAA sha256 md5-AAAA"); len(got) != 0 {
		t.Errorf("sriHashes accepted %+v", got)
	}
	if got := sriHashes(sdkSRI + "?opt"); len(got) != 1 {
		t.Errorf("an SRI option was not ignored: %+v", got)
	}
	for _, in := range []string{"sha256:abc", "md5:" + serdeHex, "sha256:zz"} {
		if _, ok := hexHash(in, ""); ok {
			t.Errorf("hexHash(%q) accepted it", in)
		}
	}
}

func TestNormalisePyPI(t *testing.T) {
	for in, want := range map[string]string{
		"Wheel_Only":     "wheel-only",
		"zope.interface": "zope-interface",
		"A--B__c":        "a-b-c",
		"plain":          "plain",
		"_leading":       "leading",
	} {
		if got := normalisePyPI(in); got != want {
			t.Errorf("normalisePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- the document ----

func emitInventory(t *testing.T, inv *Inventory) (BOM, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := inv.WriteCycloneDX(&buf, "0.0.3", fixedTime); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc BOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return doc, buf.String()
}

func TestAnInventoryDocumentSaysWhatKindOfEvidenceItIs(t *testing.T) {
	inv := inspect(t, map[string]string{"package-lock.json": npmV3})
	doc, _ := emitInventory(t, inv)

	if doc.Metadata.Component == nil || doc.Metadata.Component.Type != "application" ||
		doc.Metadata.Component.Name != "mcp-weather" {
		t.Fatalf("metadata.component = %+v", doc.Metadata.Component)
	}
	var evidence, lockfile bool
	for _, p := range doc.Metadata.Properties {
		evidence = evidence || (p.Name == "passmcp:evidence" && strings.Contains(p.Value, "not read from a running artifact"))
		lockfile = lockfile || (p.Name == "passmcp:lockfile" && p.Value == "package-lock.json")
	}
	if !evidence || !lockfile {
		t.Errorf("metadata properties = %+v", doc.Metadata.Properties)
	}
	for _, c := range doc.Components {
		if c.BOMRef != c.PURL || c.Type != "library" {
			t.Errorf("component %s: ref %q type %q", c.Name, c.BOMRef, c.Type)
		}
		for _, h := range c.Hashes {
			if strings.ContainsAny(h.Content, "+/=") {
				t.Errorf("%s carries a non-hex hash %q", c.Name, h.Content)
			}
		}
		if c.Name == "typescript" && !hasProperty(c.Properties, "cdx:npm:package:development") {
			t.Error("a development dependency is not marked in the document")
		}
		if c.Name == "bare" && !hasProperty(c.Properties, "passmcp:unverifiable") {
			t.Error("an unhashed package is not marked in the document")
		}
	}
}

func hasProperty(ps []BOMProperty, name string) bool {
	for _, p := range ps {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestAnInventoryIsReproducibleAndIndependentOfWhereItLives(t *testing.T) {
	files := map[string]string{"uv.lock": uvLock}
	_, first := emitInventory(t, inspect(t, files))
	_, second := emitInventory(t, inspect(t, files))
	if first != second {
		t.Error("one lockfile in two directories gave two documents")
	}
	changed, _ := emitInventory(t, inspect(t, map[string]string{"uv.lock": strings.ReplaceAll(uvLock, "4.4.0", "4.5.0")}))
	same, _ := emitInventory(t, inspect(t, files))
	if changed.SerialNumber == same.SerialNumber {
		t.Error("a dependency change left the serial number unchanged")
	}
}

func TestAnInventoryWithNoRootStillWrites(t *testing.T) {
	doc, _ := emitInventory(t, inspect(t, map[string]string{"requirements.txt": "httpx==0.27.2\n"}))
	if doc.Metadata.Component != nil {
		t.Errorf("requirements.txt names no project, and one was invented: %+v", doc.Metadata.Component)
	}
	if err := (&Inventory{}).WriteCycloneDX(failWriter{}, "0.0.3", fixedTime); err == nil {
		t.Error("a failed write was reported as success")
	}
}
