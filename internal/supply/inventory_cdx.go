// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

// WriteCycloneDX emits the inventory as a CycloneDX 1.6 document, in the
// same shape a Go binary's is written in, so a consumer reads both the
// same way.
func (inv *Inventory) WriteCycloneDX(w io.Writer, passmcpVersion string, now time.Time) error {
	return WriteBOM(w, inv.BOM(passmcpVersion, now))
}

// BOM builds the document without writing it.
func (inv *Inventory) BOM(passmcpVersion string, now time.Time) BOM {
	doc := BOM{
		Schema:       "http://cyclonedx.org/schema/bom-" + bomSpec + ".schema.json",
		BOMFormat:    bomFormat,
		SpecVersion:  bomSpec,
		SerialNumber: inv.serialNumber(),
		Version:      1,
		Metadata: BOMMetadata{
			Timestamp:  now.UTC().Format(time.RFC3339),
			Tools:      []BOMTool{{Vendor: "sebastienrousseau", Name: "passmcp", Version: passmcpVersion}},
			Properties: inv.metadataProperties(),
		},
	}
	if inv.Root != nil {
		c := inv.Root.component("application")
		doc.Metadata.Component = &c
	}
	for _, p := range inv.Packages {
		doc.Components = append(doc.Components, p.component("library"))
	}
	return doc
}

// metadataProperties say where the inventory came from, and what kind of
// evidence it is.
func (inv *Inventory) metadataProperties() []BOMProperty {
	out := []BOMProperty{{
		// A binary's build info is what is running. A lockfile is what
		// its author says was installed. A reader weighing the document
		// should not have to know which one they are holding.
		Name:  "passmcp:evidence",
		Value: "lockfile: what the project declares was installed, not read from a running artifact",
	}}
	for _, s := range inv.Sources {
		out = append(out, BOMProperty{Name: "passmcp:lockfile", Value: s})
	}
	return out
}

// serialNumber is derived from the content, as a binary's is, so one
// project described twice gives one document. The directory is left out:
// the same lockfile checked out in two places describes the same thing.
func (inv *Inventory) serialNumber() string {
	h := sha256.New()
	if inv.Root != nil {
		_, _ = fmt.Fprintf(h, "%s\x00", inv.Root.purl())
	}
	for _, s := range inv.Sources {
		_, _ = fmt.Fprintf(h, "%s\x00", s)
	}
	for _, p := range inv.Packages {
		_, _ = fmt.Fprintf(h, "%s\x00%t\x00", p.purl(), p.Dev)
		for _, x := range p.Hashes {
			_, _ = fmt.Fprintf(h, "%s:%s\x00", x.Alg, x.Content)
		}
	}
	return uuidURN(h.Sum(nil))
}

// component renders one package.
func (p Package) component(kind string) BOMComponent {
	c := BOMComponent{
		Type:    kind,
		Name:    p.Name,
		Version: p.Version,
		PURL:    p.purl(),
		Hashes:  p.Hashes,
		private: p.Local,
	}
	c.BOMRef = c.PURL
	if p.Unverifiable != "" {
		c.Properties = append(c.Properties, BOMProperty{Name: "passmcp:unverifiable", Value: p.Unverifiable})
	}
	if p.Bundled {
		c.Properties = append(c.Properties, BOMProperty{
			Name:  "passmcp:bundled",
			Value: "shipped inside another package's archive; that archive's hash covers it",
		})
	}
	if p.Dev {
		// The name CycloneDX's own npm tooling uses, so a consumer that
		// already filters development dependencies filters these.
		c.Properties = append(c.Properties, BOMProperty{Name: "cdx:npm:package:development", Value: "true"})
	}
	return c
}
