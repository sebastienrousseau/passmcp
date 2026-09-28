// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/fleet"
	"satellion.com/passmcp/internal/ocsf"
)

var (
	fleetState        string
	fleetOutput       string
	fleetOCSFEndpoint string
	fleetOCSFHeaders  []string
)

var fleetCmd = &cobra.Command{
	Use:   "fleet",
	Short: "Validate a set of MCP servers and report what changed since the last signed run.",
}

var fleetRunCmd = &cobra.Command{
	Use:   "run <fleet.yaml>",
	Short: "Check every server in a fleet file, attest each, and diff against its previous run.",
	Long: `Check every server a fleet file names, write an attestation for each, and
compare each with its previous run: new, removed or re-annotated tools,
edited descriptions, regressed verdicts and a lower score.

A readOnlyHint that changes, or a description that gains text aimed at the
model, is critical and fails the fleet even when the score is unchanged.
A server that cannot be reached is reported as unreachable, never as a pass
and never as unchanged.

Credentials are named, never written: a server's credential block gives the
name of the environment variable that holds its token or client secret.

Exit status: 0 clean, 1 when a server was unreachable, 2 when a server failed
its gate or changed critically.`,
	Example: `  passmcp fleet run fleet.yaml
  passmcp fleet run fleet.yaml --state /data/passmcp --output json
  passmcp fleet run fleet.yaml --output ocsf --ocsf-endpoint https://siem.example/ocsf`,
	Args: cobra.ExactArgs(1),
	RunE: runFleet,
}

func init() {
	fleetRunCmd.Flags().StringVar(&fleetState, "state", "", "directory runs are kept in (default: the fleet file's state, or ./fleet-state)")
	fleetRunCmd.Flags().StringVar(&fleetOutput, "output", "text", "summary format: text, json, ocsf")
	fleetRunCmd.Flags().StringVar(&fleetOCSFEndpoint, "ocsf-endpoint", "", "post the fleet's changes as OCSF events to this endpoint (your SIEM); nothing is sent without it")
	fleetRunCmd.Flags().StringArrayVar(&fleetOCSFHeaders, "ocsf-header", nil, "extra header on the OCSF post, \"Name: value\" (repeatable)")
	fleetCmd.AddCommand(fleetRunCmd)
}

// runFleet is `passmcp fleet run`.
func runFleet(cmd *cobra.Command, args []string) error {
	switch fleetOutput {
	case "text", "json", "ocsf":
	default:
		return fmt.Errorf("--output must be text, json or ocsf, not %q", fleetOutput)
	}
	f, err := fleet.Load(args[0])
	if err != nil {
		return err
	}
	base := filepath.Dir(args[0])
	runner := fleet.Runner{
		Version:  Version,
		StateDir: stateDirFor(f, base),
		BaseDir:  base,
		Progress: func(r fleet.ServerResult) {
			diag.Infof("fleet: %s: %s%s", r.Name, r.Status, progressDetail(r))
		},
	}
	diag.Infof("fleet: checking %d server(s); runs are kept in %s", len(f.Servers), runner.StateDir)
	sum, err := runner.Run(cmd.Context(), f)
	if err != nil {
		return err
	}
	if err := writeFleetSummary(os.Stdout, sum); err != nil {
		return err
	}
	sendFleetOCSF(cmd, sum)
	if sum.Exit != fleet.ExitOK {
		osExit(sum.Exit)
	}
	return nil
}

// stateDirFor is --state, then the fleet file's own setting, then a default
// beside the fleet file.
func stateDirFor(f *fleet.File, base string) string {
	switch {
	case fleetState != "":
		return fleetState
	case f.State != "" && filepath.IsAbs(f.State):
		return f.State
	case f.State != "":
		return filepath.Join(base, f.State)
	default:
		return filepath.Join(base, "fleet-state")
	}
}

// progressDetail is the rest of a server's progress line.
func progressDetail(r fleet.ServerResult) string {
	switch {
	case r.Status == fleet.StatusUnreachable:
		return ": " + r.Error
	case len(r.Changes) > 0:
		return fmt.Sprintf(", %.1f (%s), %d change(s), worst %s", r.Score, r.Grade, len(r.Changes), r.Worst)
	case r.Previous == "":
		// Nothing to compare with is not the same as nothing changed.
		return fmt.Sprintf(", %.1f (%s), first recorded run", r.Score, r.Grade)
	default:
		return fmt.Sprintf(", %.1f (%s), unchanged", r.Score, r.Grade)
	}
}

// writeFleetSummary prints the summary in the chosen format.
func writeFleetSummary(w io.Writer, sum *fleet.Summary) error {
	switch fleetOutput {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sum)
	case "ocsf":
		return ocsf.Write(w, ocsf.FromDrift(sum.Drift(), ocsf.Options{ProductVersion: Version}))
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tSTATUS\tSCORE\tGRADE\tCHANGES\tWORST\tEXIT")
	for _, s := range sum.Servers {
		score, grade := fmt.Sprintf("%.1f", s.Score), s.Grade
		if s.Status == fleet.StatusUnreachable {
			score, grade = "-", "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%d\n", s.Name, s.Status, score, grade, len(s.Changes), dash(s.Worst), s.Exit)
	}
	return tw.Flush()
}

// sendFleetOCSF posts the changes when --ocsf-endpoint named a destination,
// announcing it first. Never fatal: the SIEM is not the fleet.
func sendFleetOCSF(cmd *cobra.Command, sum *fleet.Summary) {
	if fleetOCSFEndpoint == "" {
		return
	}
	headers := map[string]string{}
	for _, h := range fleetOCSFHeaders {
		k, v, err := creds.ParseHeader(h)
		if err != nil {
			diag.Warnf("OCSF export failed: %v", err)
			return
		}
		headers[k] = v
	}
	events := ocsf.FromDrift(sum.Drift(), ocsf.Options{ProductVersion: Version})
	diag.Infof("sending %d OCSF event(s) to %s (--ocsf-endpoint); nothing else leaves this machine", len(events), fleetOCSFEndpoint)
	if err := (ocsf.Sender{Endpoint: fleetOCSFEndpoint, Headers: headers}).Send(cmd.Context(), events); err != nil {
		diag.Warnf("OCSF export failed: %v", err)
	}
}

// dash stands in for an empty cell.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
