// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// requirements.txt is the weakest of these: it is a lockfile only when
// its author made it one. A pin (==) fixes the version; --hash fixes the
// artifact. Without both, what gets installed is whatever the index
// serves on the day, and the entry says so.

var (
	// A requirement: a name, optional extras, then a version clause.
	reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)
	reqPin  = regexp.MustCompile(`^===?\s*([^\s;,]+)$`)
	reqHash = regexp.MustCompile(`--hash[=\s]+([A-Za-z0-9]+:[0-9A-Fa-f]+)`)
)

func parseRequirements(data []byte) ([]Package, *Package, error) {
	var out []Package
	for _, line := range requirementLines(data) {
		// Options, includes and constraints: -r, -c, -e, --index-url.
		// An include is another file this does not follow, because the
		// operator named a directory and the include may name anywhere.
		if strings.HasPrefix(line, "-") {
			continue
		}
		// A URL or path requirement has no index version to pin.
		if strings.Contains(line, "://") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
			continue
		}
		hashes := reqHash.FindAllStringSubmatch(line, -1)
		spec := reqHash.ReplaceAllString(line, "")
		spec, _, _ = strings.Cut(spec, ";") // environment marker
		m := reqLine.FindStringSubmatch(strings.TrimSpace(spec))
		if m == nil {
			continue
		}
		p := Package{Ecosystem: "pypi", Name: m[1]}
		clause := strings.TrimSpace(m[3])
		if pin := reqPin.FindStringSubmatch(clause); pin != nil {
			p.Version = pin[1]
		}
		switch {
		case p.Version == "":
			p.Unverifiable = "not pinned to one version; the index decides what is installed"
		case len(hashes) == 0:
			p.Unverifiable = "pinned without --hash; the index decides which artifact is installed"
		case len(hashes) == 1:
			if h, ok := hexHash(hashes[0][1], ""); ok {
				p.Hashes = []BOMHash{h}
			} else {
				p.Unverifiable = "--hash value is not a well-formed digest"
			}
		default:
			// Several accepted artifacts, one per platform, and no way to
			// say which is the component. Pinned all the same: pip
			// refuses anything not on the list.
		}
		out = append(out, p)
	}
	return out, nil, nil
}

// requirementLines joins backslash continuations and drops comments.
func requirementLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLockfile)
	for sc.Scan() {
		line := sc.Text()
		// A comment starts at a # preceded by whitespace or at the start.
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			line = ""
		}
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`) + " ")
			continue
		}
		cur.WriteString(line)
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}
