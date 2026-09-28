// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// A module graph passmcp can read is worth little if it only exists inside
// passmcp. CycloneDX is what the rest of a platform team's tooling already
// consumes — a scanner, a registry, an artifact store — so emitting it is
// what turns "passmcp knows" into "your pipeline knows".
//
// It is written by hand rather than with a library, and that is the whole
// point of doing it this way. The document below is a few hundred lines of
// struct tags against a schema that has been stable for years; a
// dependency for it would be a dependency in the binary a security team
// has to approve, in order to describe the dependencies in somebody
// else's binary. The joke writes itself and the module graph stays at
// eight.

// bomFormat and bomSpec are the document's own identification. 1.6 is the
// current specification and the one every consumer in the field reads.
const (
	bomFormat = "CycloneDX"
	bomSpec   = "1.6"
)

// BOM is a CycloneDX software bill of materials.
type BOM struct {
	Schema       string         `json:"$schema,omitempty"`
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber,omitempty"`
	Version      int            `json:"version"`
	Metadata     BOMMetadata    `json:"metadata"`
	Components   []BOMComponent `json:"components,omitempty"`
	// Vulnerabilities are filled only when the operator asked for a
	// lookup; a document written without one says nothing about them.
	Vulnerabilities []BOMVulnerability `json:"vulnerabilities,omitempty"`
}

// BOMMetadata says who produced the document and what it describes.
type BOMMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []BOMTool     `json:"tools,omitempty"`
	Component *BOMComponent `json:"component,omitempty"`
	// Properties carry the facts CycloneDX has no field for: the
	// toolchain, the platform, and whether the tree was clean. They are
	// the provenance half of what a reader came for, and losing them in
	// translation would make this document weaker than the binary it
	// describes.
	Properties []BOMProperty `json:"properties,omitempty"`
}

// BOMTool is what wrote the document.
type BOMTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// BOMComponent is one module.
type BOMComponent struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Hashes     []BOMHash     `json:"hashes,omitempty"`
	Properties []BOMProperty `json:"properties,omitempty"`

	// private marks a component whose name should not leave the machine
	// in a vulnerability lookup: it did not come from a public registry,
	// so no public database can know it, and its name may be internal.
	private bool
}

// BOMHash is a checksum in the form CycloneDX expects.
type BOMHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// BOMProperty is a name/value pair for anything the schema does not model.
type BOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// WriteCycloneDX emits the build as a CycloneDX 1.6 document.
//
// passmcpVersion identifies the tool in the metadata, because a bill of
// materials whose producer is anonymous is one nobody can date or trust.
func (b *Build) WriteCycloneDX(w io.Writer, passmcpVersion string, now time.Time) error {
	return WriteBOM(w, b.BOM(passmcpVersion, now))
}

// BOM builds the document without writing it, so a caller can add to it
// first.
func (b *Build) BOM(passmcpVersion string, now time.Time) BOM {
	doc := BOM{
		Schema:      "http://cyclonedx.org/schema/bom-" + bomSpec + ".schema.json",
		BOMFormat:   bomFormat,
		SpecVersion: bomSpec,
		// Deterministic rather than random: the same binary described
		// twice should produce the same document, or a pipeline that
		// diffs two of them sees a change on every run and stops looking.
		SerialNumber: b.serialNumber(),
		Version:      1,
		Metadata: BOMMetadata{
			Timestamp:  now.UTC().Format(time.RFC3339),
			Tools:      []BOMTool{{Vendor: "sebastienrousseau", Name: "passmcp", Version: passmcpVersion}},
			Component:  b.mainComponent(),
			Properties: b.metadataProperties(),
		},
	}
	if c, ok := b.stdlibComponent(); ok {
		doc.Components = append(doc.Components, c)
	}
	for _, d := range b.Deps {
		doc.Components = append(doc.Components, component(d, "library"))
	}
	return doc
}

// WriteBOM encodes a document.
func WriteBOM(w io.Writer, doc BOM) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// stdlibComponent describes the standard library linked into the binary.
//
// It is in every Go binary and in none of its module list, and it is
// where most Go advisories are: a server built with an old toolchain
// carries that toolchain's net/http whatever its go.mod says. Its version
// is the toolchain's, which the binary records exactly.
func (b *Build) stdlibComponent() (BOMComponent, bool) {
	// "go1.27.1", possibly followed by " X:experiment". A development
	// toolchain ("devel go1.28-abcdef") has no release to name.
	fields := strings.Fields(b.GoVersion)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "go") {
		return BOMComponent{}, false
	}
	v := strings.TrimPrefix(fields[0], "go")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return BOMComponent{}, false
	}
	c := BOMComponent{
		Type:    "library",
		Name:    "stdlib",
		Version: v,
		PURL:    purl(Module{Path: "stdlib", Version: v}),
		Properties: []BOMProperty{{
			Name:  "passmcp:go-stdlib",
			Value: "the Go standard library linked into the binary; its version is the toolchain's",
		}},
	}
	c.BOMRef = c.PURL
	return c, true
}

// serialNumber is a URN derived from what the document describes.
//
// CycloneDX asks for a UUID. A random one would make two descriptions of
// one binary differ in a field that means nothing, so this hashes the
// identity instead and formats the result as a version-5-shaped UUID: the
// same input gives the same serial, and a different binary gives a
// different one.
func (b *Build) serialNumber() string {
	h := sha256.New()
	h.Write([]byte(b.Main.Path))
	h.Write([]byte{0})
	h.Write([]byte(b.Revision))
	h.Write([]byte{0})
	h.Write([]byte(digestOfDeps(b)))
	return uuidURN(h.Sum(nil))
}

// uuidURN formats the first sixteen bytes of a digest as a URN.
func uuidURN(sum []byte) string {
	// Set the version and variant bits so the result is a well-formed
	// UUID rather than sixteen bytes that look like one.
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	s := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

// digestOfDeps content-addresses the graph, so the serial changes when
// the dependencies do.
func digestOfDeps(b *Build) string {
	h := sha256.New()
	for _, d := range b.Deps {
		// hash.Hash never errors; the value is discarded rather than
		// checked because there is nothing to do with it.
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", d.Path, d.Version, d.Sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// mainComponent describes the binary itself.
func (b *Build) mainComponent() *BOMComponent {
	if b.Main.Path == "" {
		return nil
	}
	c := component(b.Main, "application")
	return &c
}

// metadataProperties carry what CycloneDX has no field for.
func (b *Build) metadataProperties() []BOMProperty {
	var out []BOMProperty
	add := func(k, v string) {
		if v != "" {
			out = append(out, BOMProperty{Name: k, Value: v})
		}
	}
	add("passmcp:go-version", b.GoVersion)
	add("passmcp:goos", b.GOOS)
	add("passmcp:goarch", b.GOARCH)
	add("passmcp:vcs-revision", b.Revision)
	if b.HasVCS {
		// The provenance fact worth carrying across the translation: a
		// dirty build cannot be traced to any commit, and a bill of
		// materials that omitted that would describe the parts without
		// saying the whole came from nowhere.
		add("passmcp:vcs-modified", fmt.Sprintf("%t", b.Dirty))
	}
	return out
}

// component renders one module.
func component(m Module, kind string) BOMComponent {
	c := BOMComponent{
		Type:    kind,
		Name:    m.Path,
		Version: m.Version,
		PURL:    purl(m),
	}
	c.BOMRef = c.PURL
	if c.BOMRef == "" {
		c.BOMRef = m.Path
	}
	h, ok := hashFromSum(m.Sum)
	// No checksum means the module did not come through the public
	// proxy, so no public database has heard of it, and its import path
	// may be one a company would rather keep to itself.
	c.private = strings.TrimSpace(m.Sum) == ""
	switch {
	case ok:
		c.Hashes = []BOMHash{h}
	case kind != "library" || m.Version == "":
		// Only a dependency. The main module never carries an h1: sum --
		// it is the artifact, not something fetched -- and marking it
		// unverifiable would put the warning on every document passmcp
		// emits, which is how a real one stops being read.
	case strings.TrimSpace(m.Sum) == "":
		// Said out loud rather than left blank. A dependency with no
		// checksum did not come through the module proxy, and a reader
		// scanning for unverifiable entries should not have to infer that
		// from an absence.
		c.Properties = append(c.Properties, BOMProperty{
			Name:  "passmcp:unverifiable",
			Value: "no module checksum; this did not come through the module proxy",
		})
	default:
		// The toolchain never writes a malformed sum, but the binary is
		// the server author's and its build info says whatever they put
		// there. A sum that cannot be read is as unverifiable as a
		// missing one, and dropping it silently would hide the difference.
		c.Properties = append(c.Properties, BOMProperty{
			Name:  "passmcp:unverifiable",
			Value: "module checksum is not a well-formed h1: sum",
		})
	}
	return c
}

// purl builds the package URL for a Go module.
func purl(m Module) string {
	if m.Path == "" {
		return ""
	}
	// A Go purl is namespace-qualified by import path, lower-cased, with
	// the version after an @. The path is escaped because an import path
	// may legitimately contain characters a URL will not.
	p := "pkg:golang/" + strings.TrimPrefix(url.PathEscape(m.Path), "/")
	// PathEscape escapes the slashes that separate the namespace, which
	// is not what a purl wants.
	p = strings.ReplaceAll(p, "%2F", "/")
	if m.Version != "" && m.Version != "(devel)" {
		p += "@" + url.PathEscape(m.Version)
	}
	return p
}

// hashFromSum converts a Go h1: checksum into a CycloneDX hash.
//
// h1: is a SHA-256 digest, base64-encoded, over the module's file list
// (golang.org/x/mod/sumdb/dirhash). CycloneDX requires hash content in
// hex and a schema-validating consumer rejects the whole document over
// one base64 value, so the digest is decoded and re-encoded rather than
// copied. The algorithm is declared truthfully: it is SHA-256, and the
// same bytes the checksum database vouches for.
//
// Anything that does not decode to exactly one SHA-256 digest is refused.
// A checksum in an unknown format asserted as SHA-256 is worse than none:
// a consumer would compare it and fail, or not compare it and believe it.
func hashFromSum(sum string) (BOMHash, bool) {
	sum = strings.TrimSpace(sum)
	if !strings.HasPrefix(sum, "h1:") {
		return BOMHash{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, "h1:"))
	if err != nil || len(raw) != sha256.Size {
		return BOMHash{}, false
	}
	return BOMHash{Alg: "SHA-256", Content: hex.EncodeToString(raw)}, true
}
