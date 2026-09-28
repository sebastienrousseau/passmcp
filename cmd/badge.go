// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/report"
)

// A badge is the smallest useful thing a report can become, and the only
// one that travels. A score in a CI log is read once by the person who ran
// it; the same score in a README is read by everybody who evaluates the
// server afterwards, including the people deciding whether to point an
// agent at it.
//
// It emits the shields.io endpoint document rather than an image, which
// means no image generation here, no service to run, and a badge whose
// colour and number come from a file the repository already publishes. A
// project commits the JSON and points shields at it.

// badgeLabel is the left-hand side, overridable for a project that runs
// passmcp against several servers and needs to tell the badges apart.
var badgeLabel string

// badgeEndpoint is the shields.io endpoint schema.
//
// Only the fields with a reason to be here: an endpoint document is a
// public contract and every optional field added is one somebody has to
// keep meaning what it said.
type badgeEndpoint struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
	// IsError tells shields to render the badge in its error style, for a
	// run that never reached a verdict. A badge that showed 0/100 for "the
	// endpoint was down" would be a lie in the direction that matters.
	IsError bool `json:"isError,omitempty"`
}

// badgeColor maps a grade to a shields colour.
//
// Derived from the grade rather than from the number, so the badge and the
// report cannot disagree about where a boundary is. The grade's own
// thresholds are A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40.
func badgeColor(grade string) string {
	switch grade {
	case "A":
		return "brightgreen"
	case "B":
		return "green"
	case "C":
		return "yellow"
	case "D":
		return "orange"
	default:
		return "red"
	}
}

// badgeFor renders one report as an endpoint document.
func badgeFor(rep report.Report, label string) badgeEndpoint {
	b := badgeEndpoint{SchemaVersion: 1, Label: label}

	// A run that never reached a verdict has no score to show. Saying so
	// is the whole point: the failure mode this guards against is a
	// pipeline that goes green because the endpoint was down.
	if rep.Score.Of == 0 || rep.Score.Assessed == 0 {
		b.Message = "no verdict"
		b.Color = "lightgrey"
		b.IsError = true
		return b
	}

	b.Message = fmt.Sprintf("%d/100", int(math.Round(rep.Score.Total)))
	if rep.Score.Grade != "" {
		b.Message += " " + rep.Score.Grade
	}
	b.Color = badgeColor(rep.Score.Grade)
	return b
}

var badgeCmd = &cobra.Command{
	Use:   "badge [report.json]",
	Short: "Turn a saved JSON report into a shields.io badge endpoint.",
	Long: `Read a JSON report and write the shields.io endpoint document for it.

A badge is a score that travels. The number in a CI log is read once, by
whoever ran it; the same number in a README is read by everybody deciding
whether to point an agent at the server.

  passmcp check URL --output json > report.json
  passmcp badge report.json > badge.json

Commit badge.json somewhere it is served over HTTPS, then point shields at
it:

  ![passmcp](https://img.shields.io/endpoint?url=https://example.com/badge.json)

With no argument, or with -, the report is read from standard input.

The colour follows the report's own grade, so the badge cannot disagree
with the document it came from. A run that never reached a verdict renders
as an error rather than as a low score: a pipeline that went green because
the endpoint was down is the failure this exists to avoid, and a badge
reading 0/100 would repeat it.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := readInput(args)
		if err != nil {
			return err
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			return fmt.Errorf("that is not a passmcp JSON report: %w", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(badgeFor(rep, badgeLabel))
	},
}

func init() {
	badgeCmd.Flags().StringVar(&badgeLabel, "label", "passmcp",
		"the badge's left-hand text, for a project badging more than one server")
}
