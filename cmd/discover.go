// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"satellion.com/passmcp/internal/diag"
	"satellion.com/passmcp/internal/discover"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/telemetry"
)

// discoverFlags are passmcp discover's options.
type discoverFlags struct {
	targets     []string
	configs     []string
	gateways    []string
	registries  []string
	registryURL string
	paths       []string
	validate    bool
	graphDir    string
	reportDir   string
	statePath   string
	output      string
	rps         float64
	concurrency int
	timeout     time.Duration
}

var discoverOpts discoverFlags

// discoverBase is the transport discovery's requests finally use; tests
// point it at fakes.
var discoverBase http.RoundTripper

// discoverChecker runs the read-only check for --validate; tests replace it.
var discoverChecker = func(rps float64, concurrency int) discover.Checker {
	return discover.EngineChecker(Version, rps, concurrency)
}

// discoverCmd finds MCP endpoints among targets the operator names.
var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Find MCP endpoints among targets you name, and prove each one.",
	Long: `Probe the targets you name for MCP endpoints, and prove each one.

passmcp contacts only the hosts you list, at a few well-known paths (/mcp,
/sse, and the /.well-known documents that point at an endpoint), and never
scans a range, follows a redirect to another host, or reads a server card's
link to one. An endpoint counts only when it completes an MCP handshake, or
answers server/discover, and the request that showed it is cited as req#N.

Targets come from sources you name:

  --targets FILE            hostnames or URLs, one per line
  --from-config FILE        an MCP client configuration (Claude Desktop,
                            Cursor, VS Code, Zed): its remote servers
  --from-gateway FILE       an agentgateway or Obot configuration: every
                            URL it declares
  --from-registry NS        the MCP Registry, limited to your own namespace
                            (io.github.<org>); nothing outside it

An endpoint that lists its tools to a client with no credentials is
reported as critical: exposed without authentication. With --validate each
endpoint also gets the full read-only check and an attestation, and with
--graph they land in a passmcp-graph store beside their sources.

  passmcp discover --targets targets.txt
  passmcp discover --from-config ~/.cursor/mcp.json --validate --report-dir out
  passmcp discover --targets targets.txt --state discovery-state.json --output sarif

Exit status is 2 when an endpoint is exposed without authentication, 0
otherwise, and 1 when discovery could not run.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runDiscover(cmd.Context(), cmd.OutOrStdout(), discoverOpts)
	},
}

func init() {
	f := discoverCmd.Flags()
	o := &discoverOpts
	f.StringArrayVar(&o.targets, "targets", nil, "file of hostnames or URLs to probe, one per line (repeatable)")
	f.StringArrayVar(&o.configs, "from-config", nil, "MCP client configuration whose remote servers become targets (repeatable)")
	f.StringArrayVar(&o.gateways, "from-gateway", nil, "gateway configuration whose URLs become targets (repeatable)")
	f.StringArrayVar(&o.registries, "from-registry", nil, "registry namespace you own, such as io.github.example (repeatable)")
	f.StringVar(&o.registryURL, "registry-url", "https://registry.modelcontextprotocol.io", "MCP Registry base URL for --from-registry")
	f.StringSliceVar(&o.paths, "paths", nil, "paths to probe on each target (default "+strings.Join(discover.DefaultPaths, ",")+")")
	f.BoolVar(&o.validate, "validate", false, "run the read-only check against each endpoint and write an attestation")
	f.StringVar(&o.graphDir, "graph", "", "passmcp-graph store to record endpoints, sources and attestations in")
	f.StringVar(&o.reportDir, "report-dir", "", "write discovery.json, discovery.sarif, telemetry.ndjson and attestations here")
	f.StringVar(&o.statePath, "state", "", "state file from a previous run, to report new and disappeared endpoints")
	f.StringVar(&o.output, "output", "text", "output format: text, json or sarif")
	f.Float64Var(&o.rps, "rps", 2, fmt.Sprintf("max requests per second across the run, at most %d; 0 or negative disables throttling", engine.MaxRPS))
	f.IntVar(&o.concurrency, "concurrency", 4, fmt.Sprintf("targets probed at once, at most %d", engine.MaxConcurrency))
	f.DurationVar(&o.timeout, "timeout", 10*time.Second, "per-request timeout")
}

// runDiscover is the whole command.
func runDiscover(ctx context.Context, stdout io.Writer, o discoverFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := checkDiscoverFlags(o); err != nil {
		return err
	}
	targets, err := discoverTargets(ctx, o)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("discover: no targets; name them with --targets, --from-config, --from-gateway or --from-registry")
	}
	rec := telemetry.New()
	diag.Infof("probing %d targets named by the operator, nothing else", len(targets))
	res := discover.Run(ctx, discover.Options{
		Targets: targets, Paths: o.paths, RPS: o.rps, Concurrency: o.concurrency,
		Timeout: o.timeout, Recorder: rec, Base: discoverBase, UserAgent: "passmcp/" + Version + " (discover)",
	})
	if err := finishDiscover(ctx, o, res, rec); err != nil {
		return err
	}
	if err := writeDiscover(stdout, o.output, res); err != nil {
		return err
	}
	if res.Exposed() > 0 {
		osExit(2)
	}
	return nil
}

// checkDiscoverFlags rejects combinations that cannot work.
func checkDiscoverFlags(o discoverFlags) error {
	switch o.output {
	case "text", "json", "sarif":
	default:
		return fmt.Errorf("discover: --output must be text, json or sarif, not %q", o.output)
	}
	if o.concurrency < 1 {
		return errors.New("discover: --concurrency must be at least 1")
	}
	if err := engine.ValidatePace(o.rps, o.concurrency); err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	return nil
}

// finishDiscover compares with the previous run, validates, records the
// graph and writes the report directory, in that order.
func finishDiscover(ctx context.Context, o discoverFlags, res *discover.Result, rec *telemetry.Recorder) error {
	if o.statePath != "" {
		st, err := discover.LoadState(o.statePath)
		if err != nil {
			return err
		}
		st.Compare(res)
		if err := st.Save(o.statePath); err != nil {
			return err
		}
	}
	if o.validate {
		dir := o.reportDir
		if dir == "" {
			dir = "passmcp-discovery"
		}
		if err := discover.Validate(ctx, res, discoverChecker(o.rps, o.concurrency), dir); err != nil {
			return err
		}
	}
	if o.graphDir != "" {
		if err := discover.SaveGraph(o.graphDir, res); err != nil {
			return err
		}
	}
	if o.reportDir != "" {
		return writeDiscoverDir(o.reportDir, res, rec)
	}
	return nil
}

// writeDiscover renders the result on stdout.
func writeDiscover(w io.Writer, format string, res *discover.Result) error {
	switch format {
	case "json":
		return discover.WriteJSON(w, res)
	case "sarif":
		return discover.WriteSARIF(w, res, Version)
	default:
		discover.WriteText(w, res)
		return nil
	}
}

// writeDiscoverDir writes every rendering and the telemetry the req#N
// citations point into.
func writeDiscoverDir(dir string, res *discover.Result, rec *telemetry.Recorder) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	writers := map[string]func(io.Writer) error{
		"discovery.json":   func(w io.Writer) error { return discover.WriteJSON(w, res) },
		"discovery.sarif":  func(w io.Writer) error { return discover.WriteSARIF(w, res, Version) },
		"telemetry.ndjson": rec.WriteNDJSON,
	}
	for name, write := range writers {
		if err := writeDiscoverFile(filepath.Join(dir, name), write); err != nil {
			return err
		}
	}
	diag.Infof("saved the discovery report and telemetry to %s", dir)
	return nil
}

// writeDiscoverFile writes one file through write.
func writeDiscoverFile(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- under the directory the operator named
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// discoverTargets gathers the targets from every named source.
func discoverTargets(ctx context.Context, o discoverFlags) ([]discover.Target, error) {
	var out []discover.Target
	for _, path := range o.targets {
		f, err := os.Open(path) // #nosec G304 -- the operator named the file
		if err != nil {
			return nil, err
		}
		t, err := discover.ParseTargets(f, path)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, t...)
	}
	fromFiles, err := discoverFileSources(o)
	if err != nil {
		return nil, err
	}
	out = append(out, fromFiles...)
	client := &http.Client{Timeout: o.timeout, Transport: discoverBase}
	for _, ns := range o.registries {
		diag.Infof("reading the MCP Registry at %s for namespace %s only", o.registryURL, ns)
		t, err := discover.FromRegistry(ctx, client, o.registryURL, ns)
		if err != nil {
			return nil, fmt.Errorf("--from-registry %s: %w", ns, err)
		}
		out = append(out, t...)
	}
	return out, nil
}

// discoverFileSources reads the client and gateway configurations.
func discoverFileSources(o discoverFlags) ([]discover.Target, error) {
	var out []discover.Target
	for _, path := range o.configs {
		b, err := discover.ReadFile(path)
		if err != nil {
			return nil, err
		}
		t, err := discover.FromClientConfig(b, path)
		if err != nil {
			return nil, err
		}
		out = append(out, t...)
	}
	for _, path := range o.gateways {
		b, err := discover.ReadFile(path)
		if err != nil {
			return nil, err
		}
		out = append(out, discover.FromGatewayConfig(b, path)...)
	}
	return out, nil
}
