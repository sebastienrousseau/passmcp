// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cra

import (
	"path"
	"regexp"
	"strings"
)

// repoURL is the prefix of a link into passmcp's own repository. A link of
// this form is evidence only if the file it names exists on disk.
const repoURL = "https://github.com/sebastienrousseau/passmcp/"

var (
	mdLink     = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
	listItem   = regexp.MustCompile(`^\s*[-*]\s+`)
	repoBranch = regexp.MustCompile(`^(?:blob|tree)/[^/]+/(.+)$`)
)

// claims splits the Markdown into its list items, each with its
// continuation lines. A claim is a list item: that is the convention the
// compliance pages follow, one checkable statement per bullet.
func claims(md string) []string {
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
		}
		cur = ""
	}
	for _, line := range strings.Split(md, "\n") {
		switch {
		case listItem.MatchString(line):
			flush()
			cur = strings.TrimSpace(line)
		case strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#"):
			flush()
		case cur != "":
			cur += " " + strings.TrimSpace(line)
		}
	}
	flush()
	return out
}

// target resolves a link to a repository path, or "" for a link that is
// not into the repository (an external source, such as the regulation).
func target(link, docPath string) string {
	link, _, _ = strings.Cut(link, "#")
	switch {
	case link == "":
		return "" // an in-page anchor
	case strings.HasPrefix(link, repoURL):
		m := repoBranch.FindStringSubmatch(strings.TrimPrefix(link, repoURL))
		if m == nil {
			return ""
		}
		return strings.TrimSuffix(m[1], "/")
	case strings.Contains(link, "://") || strings.HasPrefix(link, "mailto:"):
		return ""
	default:
		return path.Clean(path.Join(path.Dir(docPath), link))
	}
}

// CheckClaims returns the claims on a compliance page that carry no
// evidence: a list item with no link at all, or a link into the repository
// whose file does not exist. docPath is the page's path in the repository,
// against which relative links resolve, and exists reports whether a
// repository path exists.
func CheckClaims(md, docPath string, exists func(repoPath string) bool) []string {
	var problems []string
	for _, c := range claims(md) {
		links := mdLink.FindAllStringSubmatch(c, -1)
		if len(links) == 0 {
			problems = append(problems, docPath+": a claim links to no evidence: "+truncateClaim(c))
			continue
		}
		for _, l := range links {
			if t := target(l[1], docPath); t != "" && !exists(t) {
				problems = append(problems, docPath+": evidence "+t+" does not exist (in: "+truncateClaim(c)+")")
			}
		}
	}
	return problems
}

// truncateClaim keeps a problem message readable when a claim is long.
func truncateClaim(c string) string {
	const max = 90
	if len(c) <= max {
		return c
	}
	return c[:max] + "…"
}
