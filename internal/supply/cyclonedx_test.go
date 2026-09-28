// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// A bill of materials is read by machines, so the tests decode it rather
// than matching strings: what matters is that a scanner pointed at the
// document finds the fields where the specification says they are.

var fixedTime = time.Date(2026, 9, 22, 10, 30, 0, 0, time.UTC)

// sampleBuild is a graph with one verifiable dependency and one that never
// came through the proxy.
func sampleBuild() *Build {
	return &Build{
		Path:      "/usr/local/bin/mcp-server",
		GoVersion: "go1.27.1",
		GOOS:      "linux",
		GOARCH:    "amd64",
		Revision:  "9062e36eda9706ffcf95911419b3fa632e045d11",
		HasVCS:    true,
		Main:      Module{Path: "example.com/server", Version: "v1.2.3"},
		Deps: []Module{
			{Path: "github.com/spf13/cobra", Version: "v1.8.1", Sum: "h1:e5/vxKd/rZsfSJMUX1agtjeTDf+qv1/JdBF8gg5k9ZM="},
			{Path: "example.com/vendored", Version: "v0.0.0-00010101000000-000000000000"},
		},
	}
}

// emit renders the build and decodes it.
func emit(t *testing.T, b *Build) (BOM, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := b.WriteCycloneDX(&buf, "0.0.3", fixedTime); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc BOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("what was written is not JSON: %v\n%s", err, buf.String())
	}
	return doc, buf.String()
}

// TestDocumentIdentifiesItself. A consumer decides how to parse the file
// from these three fields, so getting one wrong makes the whole document
// unreadable rather than merely wrong.
func TestDocumentIdentifiesItself(t *testing.T) {
	doc, raw := emit(t, sampleBuild())

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q", doc.SpecVersion)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if !strings.Contains(raw, `"$schema"`) {
		t.Error("no $schema, so a validator has nothing to resolve")
	}
	if doc.Metadata.Timestamp != "2026-09-22T10:30:00Z" {
		t.Errorf("timestamp = %q, want the time it was given", doc.Metadata.Timestamp)
	}
	if len(doc.Metadata.Tools) != 1 || doc.Metadata.Tools[0].Name != "passmcp" ||
		doc.Metadata.Tools[0].Version != "0.0.3" {
		t.Errorf("the document does not say what wrote it: %+v", doc.Metadata.Tools)
	}
}

// TestSerialNumberIsAUUIDURN, because CycloneDX says so and a consumer
// that validates the shape will reject anything else.
func TestSerialNumberIsAUUIDURN(t *testing.T) {
	doc, _ := emit(t, sampleBuild())

	s := doc.SerialNumber
	if !strings.HasPrefix(s, "urn:uuid:") {
		t.Fatalf("serialNumber = %q, not a URN", s)
	}
	hex := strings.TrimPrefix(s, "urn:uuid:")
	if parts := strings.Split(hex, "-"); len(parts) != 5 ||
		len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Fatalf("serialNumber = %q, not 8-4-4-4-12", s)
	}
	// Version 5 and the RFC 4122 variant, so it is a well-formed UUID and
	// not sixteen bytes that happen to be the right length.
	if hex[14] != '5' {
		t.Errorf("version nibble = %q, want 5", hex[14])
	}
	if !strings.ContainsRune("89ab", rune(hex[19])) {
		t.Errorf("variant nibble = %q, want one of 89ab", hex[19])
	}
}

// TestTheSameBinaryGivesTheSameDocument is the reason the serial is
// derived rather than generated. A pipeline that diffs two of these should
// see dependency changes and nothing else.
func TestTheSameBinaryGivesTheSameDocument(t *testing.T) {
	_, first := emit(t, sampleBuild())
	_, second := emit(t, sampleBuild())
	if first != second {
		t.Error("two descriptions of one binary differ")
	}
}

// TestTheSerialTracksWhatChanged: a different graph is a different
// document, or the serial is decoration.
func TestTheSerialTracksWhatChanged(t *testing.T) {
	base := sampleBuild().serialNumber()

	bumped := sampleBuild()
	bumped.Deps[0].Version = "v1.9.0"
	if bumped.serialNumber() == base {
		t.Error("a dependency bump did not change the serial")
	}

	moved := sampleBuild()
	moved.Revision = "0000000000000000000000000000000000000000"
	if moved.serialNumber() == base {
		t.Error("a different commit did not change the serial")
	}

	renamed := sampleBuild()
	renamed.Main.Path = "example.com/other"
	if renamed.serialNumber() == base {
		t.Error("a different module did not change the serial")
	}
}

// TestDependenciesCarryPurlsAndChecksums. The checksum is what makes this
// an inventory somebody can verify rather than a list somebody can edit.
func TestDependenciesCarryPurlsAndChecksums(t *testing.T) {
	doc, _ := emit(t, sampleBuild())

	// The standard library, then the two modules.
	if len(doc.Components) != 3 {
		t.Fatalf("want three components, got %d", len(doc.Components))
	}
	cobra := componentNamed(t, doc, "github.com/spf13/cobra")
	if cobra.Type != "library" {
		t.Errorf("type = %q, want library", cobra.Type)
	}
	if want := "pkg:golang/github.com/spf13/cobra@v1.8.1"; cobra.PURL != want {
		t.Errorf("purl = %q, want %q", cobra.PURL, want)
	}
	if cobra.BOMRef != cobra.PURL {
		t.Errorf("bom-ref = %q, want it to match the purl", cobra.BOMRef)
	}
	if len(cobra.Hashes) != 1 || cobra.Hashes[0].Alg != "SHA-256" {
		t.Fatalf("no usable hash: %+v", cobra.Hashes)
	}
	// The h1: prefix and the base64 are Go's, not CycloneDX's. The schema
	// requires hex, and a validating consumer rejects the whole document
	// over one base64 value, so the digest must arrive re-encoded.
	if want := "7b9fefc4a77fad9b1f4893145f56a0b637930dffaabf5fc974117c820e64f593"; cobra.Hashes[0].Content != want {
		t.Errorf("hash content = %q, want the h1: digest in hex %q", cobra.Hashes[0].Content, want)
	}
}

// TestAMalformedSumIsMarkedNotDropped. The build info is the server
// author's to write, and a sum that cannot be decoded is as unverifiable
// as a missing one.
func TestAMalformedSumIsMarkedNotDropped(t *testing.T) {
	c := component(Module{Path: "example.com/forged", Version: "v1.0.0", Sum: "h1:not-base64!"}, "library")
	if len(c.Hashes) != 0 {
		t.Errorf("a malformed sum became a hash: %+v", c.Hashes)
	}
	if len(c.Properties) != 1 || c.Properties[0].Name != "passmcp:unverifiable" ||
		!strings.Contains(c.Properties[0].Value, "well-formed") {
		t.Fatalf("a malformed sum was not marked: %+v", c.Properties)
	}
}

// TestAnUnverifiableDependencySaysSo. An absent hash is indistinguishable
// from an oversight, and a reader scanning for what cannot be verified
// should not have to infer it.
func TestAnUnverifiableDependencySaysSo(t *testing.T) {
	doc, _ := emit(t, sampleBuild())

	vendored := componentNamed(t, doc, "example.com/vendored")
	if len(vendored.Hashes) != 0 {
		t.Errorf("a module with no sum was given a hash: %+v", vendored.Hashes)
	}
	if len(vendored.Properties) != 1 || vendored.Properties[0].Name != "passmcp:unverifiable" {
		t.Fatalf("nothing marks it unverifiable: %+v", vendored.Properties)
	}
}

// TestTheMainModuleIsNotMarkedUnverifiable. It never carries an h1: sum --
// it is the artifact, not something fetched -- so marking it would put the
// warning on every document passmcp emits, which is how a real one stops
// being read.
func TestTheMainModuleIsNotMarkedUnverifiable(t *testing.T) {
	doc, _ := emit(t, sampleBuild())

	main := doc.Metadata.Component
	if main == nil {
		t.Fatal("no metadata.component, so the document does not say what it describes")
	}
	if main.Type != "application" {
		t.Errorf("type = %q, want application", main.Type)
	}
	if len(main.Properties) != 0 {
		t.Errorf("the main module was marked: %+v", main.Properties)
	}
}

// TestProvenanceTravelsAsProperties. CycloneDX has no field for a dirty
// tree, and a document that dropped it would say less than the binary.
func TestProvenanceTravelsAsProperties(t *testing.T) {
	doc, _ := emit(t, sampleBuild())

	got := map[string]string{}
	for _, p := range doc.Metadata.Properties {
		got[p.Name] = p.Value
	}
	for k, want := range map[string]string{
		"passmcp:go-version":   "go1.27.1",
		"passmcp:goos":         "linux",
		"passmcp:goarch":       "amd64",
		"passmcp:vcs-modified": "false",
		"passmcp:vcs-revision": "9062e36eda9706ffcf95911419b3fa632e045d11",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}

	dirty := sampleBuild()
	dirty.Dirty = true
	doc, _ = emit(t, dirty)
	for _, p := range doc.Metadata.Properties {
		if p.Name == "passmcp:vcs-modified" && p.Value != "true" {
			t.Errorf("a dirty build reported %q", p.Value)
		}
	}
}

// TestNoVCSStampSaysNothingRatherThanClean. A build from a source archive
// carries no stamp, and reporting vcs-modified=false for it would be a
// claim nobody made.
func TestNoVCSStampSaysNothingRatherThanClean(t *testing.T) {
	b := sampleBuild()
	b.HasVCS, b.Revision = false, ""
	doc, _ := emit(t, b)

	for _, p := range doc.Metadata.Properties {
		if p.Name == "passmcp:vcs-modified" || p.Name == "passmcp:vcs-revision" {
			t.Errorf("a build with no stamp reported %s=%q", p.Name, p.Value)
		}
	}
}

// TestAToolchainBinaryStillProducesAValidDocument. `go` itself has no main
// module path and no dependencies; emitting a document with an empty
// component object would fail validation for no reason. Its standard
// library is still in it, and is still listed.
func TestAToolchainBinaryStillProducesAValidDocument(t *testing.T) {
	doc, _ := emit(t, &Build{GoVersion: "go1.27.1"})

	if doc.Metadata.Component != nil {
		t.Errorf("a nameless main module became a component: %+v", doc.Metadata.Component)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "stdlib" {
		t.Errorf("components = %+v, want only the standard library", doc.Components)
	}
	_, raw := emit(t, &Build{})
	if strings.Contains(raw, `"components"`) {
		t.Errorf("an empty component list was written:\n%s", raw)
	}
}

// TestTheStandardLibraryIsAComponent. It is linked into every Go binary,
// appears in no module list, and is where most Go advisories are.
func TestTheStandardLibraryIsAComponent(t *testing.T) {
	doc, _ := emit(t, sampleBuild())
	std := componentNamed(t, doc, "stdlib")
	if std.Version != "1.27.1" || std.PURL != "pkg:golang/stdlib@1.27.1" {
		t.Errorf("stdlib = %+v", std)
	}
	if hasProperty(std.Properties, "passmcp:unverifiable") {
		t.Error("the standard library was marked unverifiable; it has no module checksum to carry")
	}
	for _, v := range []string{"go1.27.1 X:boringcrypto", "go1.27.1"} {
		if c, ok := (&Build{GoVersion: v}).stdlibComponent(); !ok || c.Version != "1.27.1" {
			t.Errorf("%q gave %+v %v", v, c, ok)
		}
	}
	for _, v := range []string{"", "devel go1.28-abcdef", "go", "gofoo"} {
		if _, ok := (&Build{GoVersion: v}).stdlibComponent(); ok {
			t.Errorf("%q named a standard library release", v)
		}
	}
}

func componentNamed(t *testing.T, doc BOM, name string) BOMComponent {
	t.Helper()
	for _, c := range doc.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no component named %s in %+v", name, doc.Components)
	return BOMComponent{}
}

func TestPurl(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Module
		want string
	}{
		{"ordinary", Module{Path: "github.com/spf13/cobra", Version: "v1.8.1"},
			"pkg:golang/github.com/spf13/cobra@v1.8.1"},
		{"major version suffix", Module{Path: "github.com/a/b/v2", Version: "v2.0.1"},
			"pkg:golang/github.com/a/b/v2@v2.0.1"},
		// (devel) is the toolchain saying it does not know, and a purl
		// carrying it would be a version string nobody can resolve.
		{"devel", Module{Path: "example.com/x", Version: "(devel)"}, "pkg:golang/example.com/x"},
		{"no version", Module{Path: "example.com/x"}, "pkg:golang/example.com/x"},
		{"no path", Module{Version: "v1"}, ""},
		// A path is not a URL and may carry characters one cannot.
		{"escaped", Module{Path: "example.com/a b", Version: "v1"}, "pkg:golang/example.com/a%20b@v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := purl(tc.in); got != tc.want {
				t.Errorf("purl(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestAComponentWithNoPurlStillHasARef, because bom-ref is what a
// dependency graph would point at and a document full of empty ones cannot
// be cross-referenced.
func TestAComponentWithNoPurlStillHasARef(t *testing.T) {
	c := component(Module{Path: "example.com/x"}, "library")
	if c.BOMRef == "" {
		t.Error("no bom-ref")
	}
	c = component(Module{}, "library")
	if c.PURL != "" {
		t.Errorf("a pathless module got a purl: %q", c.PURL)
	}
}

// TestHashFromSumRefusesWhatItCannotConvert. A checksum in an unknown
// format asserted as SHA-256 is worse than no checksum: a consumer would
// compare it and fail, or worse, not compare it and believe it.
func TestHashFromSumRefusesWhatItCannotConvert(t *testing.T) {
	for _, in := range []string{
		"", "  ", "h2:abc", "abc",
		"h1:abc",  // not base64
		"h1:AAAA", // base64, but three bytes rather than a SHA-256
	} {
		if _, ok := hashFromSum(in); ok {
			t.Errorf("hashFromSum(%q) accepted it", in)
		}
	}
	h, ok := hashFromSum("  h1:e5/vxKd/rZsfSJMUX1agtjeTDf+qv1/JdBF8gg5k9ZM=  ")
	if !ok || h.Alg != "SHA-256" ||
		h.Content != "7b9fefc4a77fad9b1f4893145f56a0b637930dffaabf5fc974117c820e64f593" {
		t.Errorf("hashFromSum did not trim, strip and re-encode: %+v %v", h, ok)
	}
}

// failWriter refuses everything.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// TestWriteReportsAFailedWrite. A command that returned nil having written
// nothing would leave a pipeline with an empty file and a green exit code.
func TestWriteReportsAFailedWrite(t *testing.T) {
	if err := sampleBuild().WriteCycloneDX(failWriter{}, "0.0.3", fixedTime); err == nil {
		t.Fatal("a failed write was reported as success")
	}
}

// TestARealBinaryRoundTrips, because everything above is a struct somebody
// wrote by hand and the point of the package is what the toolchain
// actually embeds.
func TestARealBinaryRoundTrips(t *testing.T) {
	b, err := Inspect(buildFixture(t, false))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	doc, _ := emit(t, b)

	if doc.Metadata.Component == nil || doc.Metadata.Component.Name != "fixture.example/server" {
		t.Fatalf("the document does not name the fixture: %+v", doc.Metadata.Component)
	}
	var goVersion string
	for _, p := range doc.Metadata.Properties {
		if p.Name == "passmcp:go-version" {
			goVersion = p.Value
		}
	}
	if !strings.HasPrefix(goVersion, "go1.") {
		t.Errorf("passmcp:go-version = %q", goVersion)
	}
}
