// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/enrich"
	"satellion.com/passmcp/internal/report"
)

var (
	explainModel  string
	explainKeyEnv string
	explainURL    string
	explainOutput string
)

var explainCmd = &cobra.Command{
	Use:   "explain <report.json>",
	Short: "Write plain-language explanations beside a saved report.",
	Long: `Explain the failures and warnings in a saved JSON report, in a separate
document, without changing it.

  passmcp check https://mcp.example.com/mcp --output json > report.json
  passmcp explain report.json > explanations.md
  passmcp explain report.json --model claude-sonnet-5 > explanations.md

By default nothing is sent: the document is every failure and warning with
passmcp's own guidance. With --model, and an Anthropic API key in
ANTHROPIC_API_KEY (or the variable named by --api-key-env), each finding is
sent to that model and its answer is printed beside the guidance, marked
as the model's. What is sent is each finding's id, title, status, severity and
detail as the report records them, and the remediation text passmcp ships;
not the evidence, the telemetry, the authentication summary or anything
else in the report. The destination is announced on stderr before anything
is sent.

The explanation annotates and never adjudicates. Every status, severity and
check id is copied from the report, and nothing the model says can change
one. The report file is only read.

Sending is asked for by --model on the command where it happens, never by
an API key that happens to be in the environment.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if explainOutput != "md" && explainOutput != "json" {
			return fmt.Errorf("--output %q: explain writes md or json", explainOutput)
		}
		b, err := readInput(args)
		if err != nil {
			return err
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil {
			return fmt.Errorf("not a passmcp JSON report: %w", err)
		}
		if len(rep.Phases) == 0 {
			return fmt.Errorf("the report records no phases, so there is nothing to explain")
		}

		var model enrich.Model
		unavailable := ""
		key := os.Getenv(explainKeyEnv)
		switch {
		case strings.TrimSpace(explainModel) == "":
			unavailable = "no model was asked for (pass --model, with an API key in " + explainKeyEnv + ")"
		case strings.TrimSpace(key) == "":
			return fmt.Errorf("--model %s needs an API key in %s (or name another variable with --api-key-env)", explainModel, explainKeyEnv)
		default:
			if err := explainURLAllowed(explainURL); err != nil {
				return err
			}
			items, _ := enrich.Items(&rep)
			if len(items) > 0 {
				diag.Infof("explain: sending %d findings (id, title, status, severity, detail and passmcp's guidance) to %s; nothing else from the report leaves this machine",
					len(items), explainURL)
			}
			model = &enrich.Anthropic{URL: explainURL, Key: key, Model: explainModel}
		}

		doc := enrich.Build(cmd.Context(), &rep, model, unavailable)
		if doc.Unavailable != "" && model != nil {
			diag.Warnf("explain: %s", doc.Unavailable)
		}
		if explainOutput == "json" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(doc)
		}
		return doc.Markdown(cmd.OutOrStdout())
	},
}

// explainURLAllowed keeps findings off the network in the clear. Loopback
// is allowed over plain HTTP, for a local proxy or a test.
func explainURLAllowed(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--api-url %q is not a URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("--api-url %q: findings are sent only over https, or plain http to this machine", raw)
}

func init() {
	f := explainCmd.Flags()
	f.StringVar(&explainModel, "model", "", "send the findings to this model, e.g. "+enrich.DefaultModel+" (off by default: nothing is sent)")
	f.StringVar(&explainKeyEnv, "api-key-env", "ANTHROPIC_API_KEY", "environment variable holding the API key")
	f.StringVar(&explainURL, "api-url", enrich.DefaultURL, "Messages API origin, for a proxy or gateway")
	f.StringVar(&explainOutput, "output", "md", "output format: md or json")
}
