// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/supply"
)

// The supply phase already reads a Go server's module graph out of the
// binary, and until now that graph only ever became two findings. This is
// the same read, emitted in the format the rest of a platform team's
// tooling already consumes.
//
// It is a separate command rather than a field on the report because the
// two documents answer to different readers. A report is read by whoever
// ran it; a bill of materials is ingested by a scanner, a registry, or an
// artifact store, and those want CycloneDX and nothing else in the file.
//
// No network, and nothing is executed: the program named is opened and
// read, not run.

// sbomCmd emits a CycloneDX document for a server binary or project.
var sbomCmd = &cobra.Command{
	Use:   "sbom <program|directory>",
	Short: "Emit a CycloneDX bill of materials for a server binary or project.",
	Long: `Write what a server is made of as CycloneDX 1.6.

  passmcp sbom ./mcp-server > bom.json        # a Go binary
  passmcp sbom ./my-ts-server > bom.json      # a project directory
  passmcp sbom mcp-server | grep unverifiable

Given a Go program, the module graph embedded in it is read. The program is
resolved through PATH, the way a shell would resolve it, and is opened and
read, never executed. Every dependency the toolchain linked in is emitted
with its package URL and its h1: module checksum. The toolchain, the target
platform, the commit and whether the tree was dirty when it was built travel
as metadata properties, because CycloneDX has no field for them and a bill
of materials that dropped them would say less than the binary does.

Given a directory, its lockfiles are read: package-lock.json, uv.lock,
Cargo.lock and requirements.txt, every one present. Only the directory
itself is read, never node_modules. Each package carries the hash its
package manager recorded. A lockfile is what the project declares was
installed rather than what is running, and the document says so in a
passmcp:evidence property.

Either way, an entry nothing can verify (no checksum, a git or local-path
source, a requirement with no pin or no --hash) is marked
passmcp:unverifiable with the reason, rather than left silently short of a
hash.

A program that is not a Go binary is an error, not an empty document: for
a TypeScript, Python or Rust server, name its project directory instead.
A server run straight from npx or uvx has no local lockfile to read.

With --osv, every component from a public registry is looked up in OSV and
the advisories that affect it are added as CycloneDX vulnerabilities. This
is the only network access the command makes, and it is off by default.
What is sent is package URLs and nothing else: no hashes, no paths, no
project name. Components from a local path, a git URL or a Go module that
never went through the public proxy are never sent. Where even public
package names are confidential, --osv-url points the lookup at a mirror.
A failed lookup fails the command rather than writing a document that
reads as clean.

  passmcp sbom ./my-ts-server --osv > bom.json

The document is reproducible: the serial number is derived from what is
being described rather than generated at random, and SOURCE_DATE_EPOCH, if
set, fixes the timestamp. The same input described twice gives the same
bytes, unless --osv is given: the advisories are the database's answer on
the day.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// A directory is a project to read lockfiles from; anything else
		// is a program. Decided by what is on disk rather than by a flag,
		// because the two cannot be confused: a directory is never an
		// executable, and a program is never read for lockfiles.
		if info, err := os.Stat(args[0]); err == nil && info.IsDir() {
			inv, err := supply.InspectDir(args[0])
			if err != nil {
				return err
			}
			return writeSBOM(cmd, inv.BOM(Version, buildTimestamp()))
		}
		build, err := supply.Inspect(args[0])
		if errors.Is(err, supply.ErrNotGo) {
			// Named as the limit it is, with the way round it. A caller
			// piping this into a scanner needs to know the difference
			// between "nothing was found" and "this was never going to
			// work here".
			return fmt.Errorf("%w; only a Go binary carries an embedded module graph. "+
				"For a TypeScript, Python or Rust server, name the project directory "+
				"instead and its lockfile is read", err)
		}
		if err != nil {
			return err
		}
		return writeSBOM(cmd, build.BOM(Version, buildTimestamp()))
	},
}

var (
	sbomOSV    bool
	sbomOSVURL string
)

func init() {
	sbomCmd.Flags().BoolVar(&sbomOSV, "osv", false,
		"look every public package up in OSV and add the advisories that affect it; the only network access this command makes")
	sbomCmd.Flags().StringVar(&sbomOSVURL, "osv-url", supply.DefaultOSVEndpoint,
		"the OSV API to ask, for a mirror when package names are confidential; https, or http to this machine")
}

// writeSBOM adds advisories when asked, then writes the document.
func writeSBOM(cmd *cobra.Command, doc supply.BOM) error {
	if sbomOSV {
		// Said before it happens, and on stderr, so stdout stays the
		// document: what is about to leave the machine, and where to.
		diag.Infof("sbom: sending %d package URLs to %s (--osv); nothing else leaves this machine",
			supply.Queryable(&doc), sbomOSVURL)
		if err := (supply.OSV{Endpoint: sbomOSVURL}).Annotate(cmd.Context(), &doc); err != nil {
			return err
		}
		diag.Infof("sbom: %d advisories affect this inventory", len(doc.Vulnerabilities))
	} else if cmd.Flags().Changed("osv-url") {
		// A mirror named without --osv would otherwise be silently
		// ignored, and the operator would believe they had asked.
		return errors.New("--osv-url names where to look; add --osv to look")
	}
	return supply.WriteBOM(os.Stdout, doc)
}

// buildTimestamp honours SOURCE_DATE_EPOCH.
//
// The serial number is already derived from what is described rather than
// generated, so the timestamp is the only field left that would make two
// descriptions of one binary differ. A pipeline that diffs yesterday's
// document against today's should see dependency changes, not a clock.
func buildTimestamp() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(secs, 0).UTC()
		}
		// A malformed value is the caller asking for reproducibility and
		// getting it wrong, which is worth saying out loud rather than
		// silently answering with the wall clock.
		diag.Warnf("ignoring SOURCE_DATE_EPOCH=%q: not an integer", v)
	}
	return time.Now().UTC()
}
