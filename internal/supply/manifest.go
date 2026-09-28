// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Most MCP servers are not Go binaries. They are TypeScript run by node,
// Python run by an interpreter, or occasionally Rust — and for those the
// executable is the runtime, which says nothing about the server. What
// does say something is the lockfile the project was installed from: the
// exact version of every package, and, when the package manager recorded
// one, the hash the registry served.
//
// Every format read here is either JSON or line-oriented TOML written by a
// machine, and each is parsed with the standard library. A TOML library
// would be the more general answer and a new module in the binary a
// security team has to approve; these files have a fixed, generated shape,
// and the readers below accept that shape and nothing more.
//
// A lockfile is a claim about what was installed, not proof of what is
// running. That limit is carried into the document as a property rather
// than left for the reader to remember.

// lockfiles are read in this order. The order only decides which appears
// first in the document: every lockfile present is read.
var lockfiles = []struct {
	name  string
	parse func([]byte) ([]Package, *Package, error)
}{
	{"package-lock.json", parseNPMLock},
	{"uv.lock", parseUVLock},
	{"Cargo.lock", parseCargoLock},
	{"requirements.txt", parseRequirements},
}

// maxLockfile bounds a single read. The directory may belong to the
// server's author, and a lockfile is the one input here whose size they
// choose; the largest real lockfiles are a few megabytes.
const maxLockfile = 64 << 20

// ErrNoManifest means the directory holds no lockfile passmcp can read.
var ErrNoManifest = errors.New("supply: no lockfile found")

// Inventory is what a project's lockfiles say it is made of.
type Inventory struct {
	// Dir is the directory that was read.
	Dir string `json:"dir"`
	// Sources are the lockfiles read, by base name, in reading order.
	Sources []string `json:"sources"`
	// Root is the project itself, when a lockfile names it.
	Root *Package `json:"root,omitempty"`
	// Packages are its dependencies, sorted by package URL.
	Packages []Package `json:"packages,omitempty"`
}

// Package is one entry of a lockfile.
type Package struct {
	// Ecosystem is the purl type: npm, pypi or cargo.
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	// Hashes are what the lockfile recorded, re-encoded as CycloneDX
	// expects: an algorithm name and hex.
	Hashes []BOMHash `json:"hashes,omitempty"`
	// Unverifiable says why nothing about this package can be checked
	// after the fact. Empty when it can be.
	Unverifiable string `json:"unverifiable,omitempty"`
	// Dev marks a package installed for development only.
	Dev bool `json:"dev,omitempty"`
	// Bundled marks a package shipped inside another's archive, which
	// that archive's hash covers.
	Bundled bool `json:"bundled,omitempty"`
	// Local marks a package installed from a path or a git URL rather
	// than a registry: no public database knows it, and its name may be
	// internal.
	Local bool `json:"local,omitempty"`
	// Source is the lockfile the entry came from.
	Source string `json:"source"`
}

// InspectDir reads every lockfile in a directory.
//
// Only the directory itself is read, not its subdirectories: a project's
// node_modules holds hundreds of lockfiles belonging to other projects,
// and none of them describes this one.
func InspectDir(dir string) (*Inventory, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("supply: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("supply: %s is not a directory", dir)
	}
	inv := &Inventory{Dir: dir}
	seen := map[string]int{}
	for _, lf := range lockfiles {
		data, err := readBounded(filepath.Join(dir, lf.name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		pkgs, root, err := lf.parse(data)
		if err != nil {
			return nil, fmt.Errorf("supply: %s: %w", lf.name, err)
		}
		inv.add(lf.name, pkgs, root, seen)
	}
	if len(inv.Sources) == 0 {
		return nil, fmt.Errorf("%w in %s (looked for %s)", ErrNoManifest, dir, lockfileNames())
	}
	sort.SliceStable(inv.Packages, func(i, j int) bool { return inv.Packages[i].purl() < inv.Packages[j].purl() })
	return inv, nil
}

// add records what one lockfile lists. seen maps a package URL to its
// index in inv.Packages, so a package several lockfiles or install paths
// name is merged into one component.
func (inv *Inventory) add(source string, pkgs []Package, root *Package, seen map[string]int) {
	inv.Sources = append(inv.Sources, source)
	if root != nil && inv.Root == nil {
		root.Source = source
		inv.Root = root
	}
	for _, p := range pkgs {
		p.Source = source
		// One package installed at several paths is one component.
		// It is a development dependency only if every copy is:
		// one production copy puts it in what ships.
		key := p.purl()
		if i, dup := seen[key]; dup {
			mergePackage(&inv.Packages[i], p)
			continue
		}
		seen[key] = len(inv.Packages)
		inv.Packages = append(inv.Packages, p)
	}
}

// mergePackage folds another copy of the same package into first.
func mergePackage(first *Package, p Package) {
	first.Dev = first.Dev && p.Dev
	// One copy with a hash makes the package verifiable:
	// it is the same name and version, so the same bytes.
	if len(first.Hashes) == 0 && len(p.Hashes) > 0 {
		first.Hashes, first.Unverifiable, first.Bundled = p.Hashes, "", false
	}
	first.Local = first.Local && p.Local
}

// lockfileNames lists what InspectDir looks for, for error messages.
func lockfileNames() string {
	names := make([]string, len(lockfiles))
	for i, lf := range lockfiles {
		names[i] = lf.name
	}
	return strings.Join(names, ", ")
}

// readBounded reads a file, refusing one larger than maxLockfile rather
// than truncating it: half a lockfile parses as a smaller project.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator named the directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxLockfile+1))
	if err != nil {
		return nil, fmt.Errorf("supply: %w", err)
	}
	if len(data) > maxLockfile {
		return nil, fmt.Errorf("supply: %s is larger than %d MiB; refusing to read part of it", path, maxLockfile>>20)
	}
	return data, nil
}

// Unpinned lists packages nothing can verify, by name.
func (inv *Inventory) Unpinned() []string {
	var out []string
	for _, p := range inv.Packages {
		if p.Unverifiable != "" {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// purl builds the package URL.
//
// npm scopes keep their @, percent-encoded as the purl specification
// requires; PyPI names are normalised the way the index normalises them,
// so two spellings of one project are one package.
func (p Package) purl() string {
	name := p.Name
	switch p.Ecosystem {
	case "npm":
		name = strings.Replace(name, "@", "%40", 1)
	case "pypi":
		name = normalisePyPI(name)
	}
	s := "pkg:" + p.Ecosystem + "/" + name
	if p.Version != "" {
		s += "@" + p.Version
	}
	return s
}

// normalisePyPI applies PEP 503: lower case, and runs of -, _ and .
// collapsed to one hyphen.
func normalisePyPI(name string) string {
	var sb strings.Builder
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep && sb.Len() > 0 {
			sb.WriteByte('-')
		}
		sep = false
		sb.WriteRune(r)
	}
	return sb.String()
}

// hashAlgs maps a lockfile's algorithm prefix to CycloneDX's name and the
// digest length, so a value that decodes to the wrong size is refused
// rather than published as a hash nobody can match.
var hashAlgs = map[string]struct {
	name string
	size int
}{
	"sha1":   {"SHA-1", 20},
	"sha256": {"SHA-256", 32},
	"sha384": {"SHA-384", 48},
	"sha512": {"SHA-512", 64},
}

// sriHashes converts an npm integrity string: one or more space-separated
// "<alg>-<base64>" entries.
func sriHashes(integrity string) []BOMHash {
	var out []BOMHash
	for _, f := range strings.Fields(integrity) {
		alg, b64, ok := strings.Cut(f, "-")
		if !ok {
			continue
		}
		// SRI allows options after a '?'; none carry digest material.
		b64, _, _ = strings.Cut(b64, "?")
		a, known := hashAlgs[alg]
		if !known {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != a.size {
			continue
		}
		out = append(out, BOMHash{Alg: a.name, Content: hex.EncodeToString(raw)})
	}
	return out
}

// hexHash converts "<alg>:<hex>", the form uv and pip write, or bare hex
// when alg is given, the form Cargo writes.
func hexHash(value, defaultAlg string) (BOMHash, bool) {
	alg, digest, ok := strings.Cut(value, ":")
	if !ok {
		alg, digest = defaultAlg, value
	}
	a, known := hashAlgs[strings.ToLower(alg)]
	if !known {
		return BOMHash{}, false
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != a.size {
		return BOMHash{}, false
	}
	return BOMHash{Alg: a.name, Content: hex.EncodeToString(raw)}, true
}
