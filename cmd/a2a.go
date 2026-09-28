// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/internal/a2a"
)

var (
	a2aOutput       string
	a2aTimeout      time.Duration
	a2aAllowPrivate bool
)

// a2aCmd groups the commands for agents that speak A2A.
var a2aCmd = &cobra.Command{
	Use:   "a2a",
	Short: "Check an agent that speaks the Agent2Agent (A2A) protocol.",
	Long: `Check an agent that speaks the Agent2Agent (A2A) protocol, from its Agent
Card, with the same evidence-backed verdicts as an MCP server.`,
}

// a2aCheckCmd checks one A2A agent.
var a2aCheckCmd = &cobra.Command{
	Use:   "check <url>",
	Short: "Fetch and verify an agent's Agent Card: transport, schema, signature and authentication.",
	Long: `Fetch the Agent Card from /.well-known/agent-card.json on the agent's
domain and check it:

  a2a.transport       the card is served over HTTPS (plain http only to
                      loopback)
  a2a.card_schema     the card is a valid A2A v1 AgentCard; every error
                      is reported with its JSON path
  a2a.card_signature  a signed card verifies over its RFC 8785 canonical
                      form, against the key its jku names
  a2a.unauthenticated the agent refuses a request with no credentials,
                      and a card that declares no scheme does not hide an
                      agent that answers anyone

Showing whether the agent serves requests takes one request: ListTasks
with a page size of one, sent with no credentials. It reads, creates and
changes nothing, and passmcp never sends a message or invokes a skill.

  passmcp a2a check https://agent.example.com
  passmcp a2a check https://agent.example.com --output attestation > a2a.json

Exit status is 0 when nothing failed, 2 when a check failed, and 1 when
the URL cannot be checked.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validA2AOutput(a2aOutput); err != nil {
			return err
		}
		res, err := a2a.Run(cmd.Context(), a2a.Options{
			URL:     args[0],
			Timeout: a2aTimeout,
			Policy:  auth.URLPolicy{AllowPrivate: a2aAllowPrivate},
		})
		if err != nil {
			return err
		}
		if err := writeA2A(cmd, res); err != nil {
			return err
		}
		if res.Failed() {
			osExit(2)
		}
		return nil
	},
}

func init() {
	fs := a2aCheckCmd.Flags()
	fs.StringVar(&a2aOutput, "output", "text", "output format: text, json or attestation")
	fs.DurationVar(&a2aTimeout, "timeout", 20*time.Second, "per-request timeout")
	fs.BoolVar(&a2aAllowPrivate, "insecure-allow-private-hosts", false, "allow a key set or interface URL the card names that resolves inside your network (off by default: a card naming one could aim passmcp at it)")
	a2aCmd.AddCommand(a2aCheckCmd)
}

func validA2AOutput(o string) error {
	switch o {
	case "text", "json", "attestation":
		return nil
	}
	return fmt.Errorf("--output %q: want text, json or attestation", o)
}

func writeA2A(cmd *cobra.Command, res *a2a.Result) error {
	w := cmd.OutOrStdout()
	switch a2aOutput {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case "attestation":
		st, err := a2a.Statement(res, Version)
		if err != nil {
			return fmt.Errorf("a2a: the statement does not validate: %w", err)
		}
		b, err := st.Marshal()
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}
	a2a.WriteText(w, res)
	return nil
}
