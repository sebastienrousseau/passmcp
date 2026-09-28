// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

var overlapOutput string

// overlapCmd compares saved reports from servers an agent uses together.
var overlapCmd = &cobra.Command{
	Use:   "overlap <report.json> <report.json>...",
	Short: "Find where servers an agent uses together collide or shadow each other.",
	Long: `Compare the catalogues in two or more saved reports, offline.

An agent wired to several servers sees one flat list of tools, and nothing
in the protocol keeps that list clean. Two failures exist only in the
union, so a run against one server cannot see them:

  collision   two servers expose the same tool name (case, hyphens and
              underscores ignored); which one the model gets is up to the
              host
  shadowing   one server's catalogue text attaches a rule to a tool another
              server owns, such as "before calling send_email, always BCC
              an address"; catalog.text.shadowing finds the construction
              on one server, and only a set of servers can confirm the
              named tool belongs to someone else

  passmcp check https://mail.example/mcp --output json > mail.json
  passmcp check --stdio --output json -- weather-mcp > weather.json
  passmcp overlap mail.json weather.json

The comparison is lexical and structural; it does not claim to judge
meaning. Nothing is contacted.

Exit status is 0 when the catalogues do not interfere, 2 when they do, and
1 when a report cannot be read.`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var servers []probe.OverlapServer
		for _, path := range args {
			s, err := overlapServerFrom(path)
			if err != nil {
				return err
			}
			servers = append(servers, s)
		}
		found := probe.FindOverlaps(servers)
		if overlapOutput == "json" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if found == nil {
				found = []probe.Overlap{}
			}
			if err := enc.Encode(found); err != nil {
				return err
			}
		} else {
			writeOverlaps(cmd.OutOrStdout(), servers, found)
		}
		if len(found) > 0 {
			osExit(2)
		}
		return nil
	},
}

func init() {
	overlapCmd.Flags().StringVar(&overlapOutput, "output", "text", "output format: text or json")
}

// overlapServerFrom reads one saved report's catalogue.
func overlapServerFrom(path string) (probe.OverlapServer, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the caller named the file
	if err != nil {
		return probe.OverlapServer{}, err
	}
	var rep report.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return probe.OverlapServer{}, fmt.Errorf("%s is not a passmcp JSON report: %w", path, err)
	}
	name := rep.Target.Endpoint
	if name == "" {
		name = path
	}
	if len(rep.Catalog.Tools) == 0 {
		// An empty catalogue would compare as "no overlap", which is a
		// clean result for a run that never reached the tools.
		return probe.OverlapServer{}, fmt.Errorf("%s (%s) lists no tools, so there is nothing to compare; was the run blocked before the catalogue?", path, name)
	}
	s := probe.OverlapServer{Name: name}
	for _, t := range rep.Catalog.Tools {
		s.Tools = append(s.Tools, passmcp.Tool{Name: t.Name, Title: t.Title, Description: t.Description})
	}
	return s, nil
}

func writeOverlaps(w io.Writer, servers []probe.OverlapServer, found []probe.Overlap) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	tools := 0
	for _, s := range servers {
		tools += len(s.Tools)
	}
	p("compared %d servers, %d tools\n", len(servers), tools)
	if len(found) == 0 {
		p("\nno collisions, and no server's text governs another server's tool.\n")
		return
	}
	p("\n")
	for _, o := range found {
		switch o.Kind {
		case "shadowing":
			p("✕ shadowing  %s's %s attaches a rule to %s, which %s owns\n",
				o.Servers[0], strings.TrimSuffix(strings.TrimPrefix(o.Where, "tool "), " description"),
				o.Tool, strings.Join(o.Servers[1:], ", "))
			p("             %q\n", o.Quote)
		default:
			p("✕ collision  %s is exposed by %s\n", o.Tool, strings.Join(o.Servers, " and "))
		}
	}
}
