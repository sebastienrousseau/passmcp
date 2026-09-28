// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// sitemap writes <root>/sitemap.xml from what is actually on disk. satellion.com
// runs it against the built satellion.com, passing its dist directory as root.
//
// The generator that ran before this produced an empty <urlset> in CI and a
// full one locally, and the difference was build order: it indexes the
// output directory, and in CI that directory is empty when it runs because
// the manual and the sample report are written afterwards. Locally they
// were still there from the previous build, so it looked right.
//
// A sitemap that depends on what happened to be left in a directory is not
// a sitemap. This walks the finished tree, so it cannot disagree with what
// was published, and it runs last for the same reason.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const base = "https://satellion.com/"

func main() {
	root := "site/dist"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	urls, err := walk(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sitemap:", err)
		os.Exit(1)
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "sitemap: no pages found under "+root+"; refusing to write an empty sitemap")
		os.Exit(1)
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, u := range urls {
		b.WriteString("  <url>\n")
		fmt.Fprintf(&b, "    <loc>%s</loc>\n", u.loc)
		fmt.Fprintf(&b, "    <lastmod>%s</lastmod>\n", u.mod.UTC().Format("2006-01-02"))
		fmt.Fprintf(&b, "    <priority>%.1f</priority>\n", u.priority)
		b.WriteString("  </url>\n")
	}
	b.WriteString("</urlset>\n")

	out := filepath.Join(root, "sitemap.xml")
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil { //nolint:gosec // a public sitemap
		fmt.Fprintln(os.Stderr, "sitemap:", err)
		os.Exit(1)
	}
	fmt.Printf("sitemap: wrote %s with %d urls\n", out, len(urls))
}

type entry struct {
	loc      string
	mod      time.Time
	priority float64
}

// walk finds every page a reader can land on. A directory's index.html is
// the directory's URL; anything else keeps its filename.
func walk(root string) ([]entry, error) {
	var out []entry
	seen := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Build scratch and asset directories hold no landing pages.
			switch info.Name() {
			case ".ssg", ".ssg-cache", ".meta", "_csp", "assets", "search", "images", "api":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".html") || info.Name() == "404.html" {
			return nil
		}
		// A page beside its own directory index is the same document at a
		// second URL — sample/report.html and sample/ are byte-identical.
		// Listing both asks a crawler to pick one, which is a question it
		// answers by dropping one of them.
		if info.Name() != "index.html" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "index.html")); err == nil {
				return nil
			}
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		rel = strings.TrimSuffix(rel, "index.html")

		loc := base + rel
		if seen[loc] {
			return nil
		}
		seen[loc] = true

		// The home page first, then the sample somebody is sent to, then
		// the manual. Priority is a hint, not a ranking, but an untuned
		// sitemap says every page matters equally, which is never true.
		p := 0.5
		switch {
		case rel == "":
			p = 1.0
		case strings.HasPrefix(rel, "sample"):
			p = 0.9
		case rel == "manual/":
			p = 0.8
		case strings.HasPrefix(rel, "manual/"):
			p = 0.6
		}
		out = append(out, entry{loc: loc, mod: info.ModTime(), priority: p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority > out[j].priority
		}
		return out[i].loc < out[j].loc
	})
	return out, nil
}
