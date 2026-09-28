// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import (
	"sort"
	"strings"
)

// artefactSuffixes are the release assets a user installs. Each must be
// accompanied by its own CycloneDX SBOM.
var artefactSuffixes = []string{".tar.gz", ".zip", ".deb", ".rpm", ".apk"}

// SBOMSuffix is the name goreleaser gives an artefact's CycloneDX SBOM.
const SBOMSuffix = ".cdx.sbom.json"

// ProvenanceSuffix is the conventional name of an in-toto bundle carrying
// SLSA build provenance.
const ProvenanceSuffix = ".intoto.jsonl"

// isArtefact reports whether an asset is something a user installs, as
// opposed to a checksum, signature, SBOM or provenance bundle.
func isArtefact(name string) bool {
	if strings.HasSuffix(name, SBOMSuffix) || strings.HasSuffix(name, ProvenanceSuffix) {
		return false
	}
	for _, s := range artefactSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// CheckReleaseAssets returns what a published release's asset list lacks:
// a CycloneDX SBOM for every installable artefact, and SLSA provenance. An
// empty result means the release carries both. A release with no
// installable artefact at all is itself a problem, because an audit that
// passes over nothing proves nothing.
func CheckReleaseAssets(assets []string) []string {
	have := make(map[string]bool, len(assets))
	for _, a := range assets {
		have[a] = true
	}
	var problems []string
	artefacts := 0
	provenance := false
	for _, a := range assets {
		if strings.HasSuffix(a, ProvenanceSuffix) {
			provenance = true
		}
		if !isArtefact(a) {
			continue
		}
		artefacts++
		if !have[a+SBOMSuffix] {
			problems = append(problems, a+" has no CycloneDX SBOM ("+a+SBOMSuffix+")")
		}
	}
	if artefacts == 0 {
		problems = append(problems, "the release has no installable artefact to audit")
	}
	if !provenance {
		problems = append(problems, "the release has no SLSA provenance bundle (*"+ProvenanceSuffix+")")
	}
	sort.Strings(problems)
	return problems
}
