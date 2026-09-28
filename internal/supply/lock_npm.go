// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// npmLock is the part of package-lock.json this reads. Version 2 and 3
// carry a flat "packages" map keyed by install path; version 1 carries a
// nested "dependencies" tree. Version 2 carries both, and the flat map is
// the one npm itself treats as authoritative.
type npmLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	Packages        map[string]npmEntry   `json:"packages"`
	Dependencies    map[string]npmV1Entry `json:"dependencies"`
}

type npmEntry struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Link      bool   `json:"link"`
	InBundle  bool   `json:"inBundle"`
}

type npmV1Entry struct {
	Version      string                `json:"version"`
	Integrity    string                `json:"integrity"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmV1Entry `json:"dependencies"`
}

func parseNPMLock(data []byte) ([]Package, *Package, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	var root *Package
	if lock.Name != "" {
		root = &Package{Ecosystem: "npm", Name: lock.Name, Version: lock.Version}
	}

	var out []Package
	switch {
	case len(lock.Packages) > 0:
		out, root = npmV2Packages(lock.Packages, root)
	case len(lock.Dependencies) > 0:
		walkNPMV1(lock.Dependencies, &out)
	case lock.LockfileVersion == 0:
		return nil, nil, errors.New("not a package-lock.json: no lockfileVersion, packages or dependencies")
	}
	return out, root, nil
}

// npmV2Packages reads the packages map of a v2 or v3 lockfile. The entry
// at the empty path is the project itself and, when named, replaces root.
func npmV2Packages(packages map[string]npmEntry, root *Package) ([]Package, *Package) {
	var out []Package
	// Sorted so the output does not depend on map order.
	paths := make([]string, 0, len(packages))
	for path := range packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		e := packages[path]
		if path == "" {
			// The project itself.
			if e.Name != "" {
				root = &Package{Ecosystem: "npm", Name: e.Name, Version: e.Version}
			}
			continue
		}
		if p, ok := npmV2Package(path, e); ok {
			out = append(out, p)
		}
	}
	return out, root
}

// npmV2Package reads one installed package, or reports false for an entry
// that is part of this project rather than something fetched.
func npmV2Package(path string, e npmEntry) (Package, bool) {
	// A link is a workspace member symlinked into node_modules:
	// part of this project, not something fetched.
	if e.Link {
		return Package{}, false
	}
	// A path outside node_modules is a workspace directory: part
	// of this project, and listed under its own name, which is
	// why the name field alone cannot decide this.
	name := npmNameFromPath(path)
	if name == "" {
		return Package{}, false
	}
	if e.Name != "" {
		// An alias installs one package under another's
		// directory; the field is the real package.
		name = e.Name
	}
	p := npmPackage(name, e.Version, e.Integrity, e.Resolved, e.Dev)
	if e.InBundle && len(p.Hashes) == 0 {
		// Shipped inside its parent's tarball rather than fetched,
		// so the parent's integrity hash already covers it. npm
		// records no hash for it because there is nothing
		// separate to download.
		p.Unverifiable = ""
		p.Bundled = true
	}
	return p, true
}

// npmNameFromPath takes the package name from an install path such as
// node_modules/a/node_modules/@scope/b.
func npmNameFromPath(path string) string {
	i := strings.LastIndex(path, "node_modules/")
	if i < 0 {
		// A workspace directory rather than an installed package.
		return ""
	}
	return path[i+len("node_modules/"):]
}

func walkNPMV1(deps map[string]npmV1Entry, out *[]Package) {
	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		e := deps[name]
		*out = append(*out, npmPackage(name, e.Version, e.Integrity, "", e.Dev))
		walkNPMV1(e.Dependencies, out)
	}
}

func npmPackage(name, version, integrity, resolved string, dev bool) Package {
	p := Package{Ecosystem: "npm", Name: name, Version: version, Dev: dev}
	p.Hashes = sriHashes(integrity)
	switch {
	case len(p.Hashes) > 0:
	case strings.TrimSpace(integrity) != "":
		p.Unverifiable = "integrity value in package-lock.json is not a well-formed SRI hash"
	case strings.HasPrefix(resolved, "file:"), strings.HasPrefix(version, "file:"):
		p.Unverifiable, p.Local = "installed from a local path; no registry hash exists", true
	case strings.HasPrefix(resolved, "git"), strings.HasPrefix(version, "git"):
		p.Unverifiable, p.Local = "installed from a git URL; no registry hash exists", true
	default:
		p.Unverifiable = "no integrity hash in package-lock.json"
	}
	return p
}
