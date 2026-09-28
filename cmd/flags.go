// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/clientconf"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/policy"
)

// Flag groups are shared FlagSets so each lands on exactly the commands
// that act on it, while every flag binds to one package-level variable.

var (
	// credentials
	authMode          string
	token             string
	tokenEnv          string
	headers           []string
	basic             string
	clientID          string
	clientSecret      string
	clientSecretEnv   string
	clientMetadataURL string
	scope             string
	params            []string
	tokenURL          string
	authURL           string
	resource          string
	redirectPort      int
	tokenAuthMethod   string
	// wrongAudienceTokenEnv names a variable holding a token issued for a
	// different resource, which auth.wrong_audience sends.
	wrongAudienceTokenEnv string
	// clientConfigFile is an MCP client configuration naming the servers
	// an agent uses together.
	clientConfigFile string

	// policy
	allowMutations   bool
	allowDestructive bool
	onlyTools        []string
	denyTools        []string
	toolArgs         []string

	// pacing
	samples     int
	concurrency int
	rps         float64
	callTimeout time.Duration
	seed        uint64
	fillOpt     bool
	allowLoad   bool

	allowPrivateHosts     bool
	userAgent             string
	allowPlaintextAuth    bool
	allowResourceMismatch bool
	skipEraCheck          bool
	policyFile            string
	baselineFile          string
	watchEgress           bool
	plantCanaries         bool
	faultUpstream         bool
	expectEgress          []string
	approveBaseline       bool
	maxRes                int
	maxPrompts            int
	soak                  int

	// output
	interactive   bool
	output        string
	reportDir     string
	retain        string
	captureBodies bool
	withEvents    bool
	withGuidance  bool
	verbose       bool
	noColor       bool
	otlpEndpoint  string
	otlpHeaders   []string
	ocsfEndpoint  string
	ocsfHeaders   []string
	phasesOnly    []string
	phasesSkip    []string
)

// target
var (
	useStdio  bool
	stdioDir  string
	stdioEnv  []string
	stdioOnly []string
)

var (
	credOnce, policyOnce, paceOnce, outOnce, targetOnce sync.Once
	credSet, policySet, paceSet, outSet, targetSet      *pflag.FlagSet
)

// targetFlags say what to point the run at.
//
// A URL is the positional argument. A program is everything after "--",
// which is the only way a command with its own flags survives the parse:
// "passmcp check --stdio -- npx -y server --verbose" hands --verbose to the
// server, where it belongs, and there is no ambiguity about whose flag it
// was. It also keeps passmcp out of the business of splitting a command
// string, which would mean quoting rules, which would mean a shell.
func targetFlags() *pflag.FlagSet {
	targetOnce.Do(func() {
		fs := pflag.NewFlagSet("target", pflag.ContinueOnError)
		fs.BoolVar(&useStdio, "stdio", false, "the server is a program to run, given after --, rather than a URL")
		fs.StringVar(&stdioDir, "stdio-dir", "", "working directory for the server process")
		fs.StringArrayVar(&stdioEnv, "stdio-env", nil, "forward this environment variable to the server by name (repeatable)")
		fs.StringArrayVar(&stdioOnly, "stdio-set", nil, "set a variable for the server as NAME=value (repeatable; replaces the forwarded set entirely)")
		targetSet = fs
	})
	return targetSet
}

func credFlags() *pflag.FlagSet {
	credOnce.Do(func() {
		fs := pflag.NewFlagSet("credentials", pflag.ContinueOnError)
		fs.StringVar(&authMode, "auth", "auto", "credential mode: auto, none, bearer, client-credentials, authorization-code")
		fs.StringVar(&token, "token", "", "pre-issued bearer token (or "+creds.EnvToken+")")
		fs.StringVar(&tokenEnv, "token-env", "", "read the bearer token from this environment variable")
		fs.StringArrayVar(&headers, "header", nil, "extra header sent on every request, \"Name: value\" (repeatable; API keys, tenant ids)")
		fs.StringVar(&basic, "basic", "", "HTTP basic credentials as user:password (or "+creds.EnvBasic+")")
		fs.StringVar(&clientID, "client-id", "", "OAuth client id (or "+creds.EnvClientID+")")
		fs.StringVar(&clientSecret, "client-secret", "", "OAuth client secret (or "+creds.EnvClientSecret+"; prefer --client-secret-env)")
		fs.StringVar(&clientSecretEnv, "client-secret-env", "", "read the client secret from this environment variable")
		fs.StringVar(&clientMetadataURL, "client-metadata-url", "", "https URL of a Client ID Metadata Document to use as client id")
		fs.StringVar(&scope, "scope", "", "scope to request (default: what the server challenge asks for)")
		fs.StringArrayVar(&params, "param", nil, "extra token/authorization request parameter key=value (repeatable; e.g. profile_id=tenant-1)")
		fs.StringVar(&tokenURL, "token-url", "", "token endpoint, bypassing discovery")
		fs.StringVar(&authURL, "auth-url", "", "authorization endpoint, bypassing discovery (with --token-url)")
		fs.StringVar(&resource, "resource", "", "RFC 8707 resource indicator override")
		fs.IntVar(&redirectPort, "redirect-port", 8976, "loopback port for the authorization-code redirect")
		fs.StringVar(&tokenAuthMethod, "token-auth-method", "", "token endpoint auth: client_secret_basic, client_secret_post or none")
		fs.StringVar(&wrongAudienceTokenEnv, "wrong-audience-token-env", "", "name of a variable holding a token your authorization server issued for a different resource; auth.wrong_audience sends it and expects a 401 (passmcp never forges one)")
		credSet = fs
	})
	return credSet
}

func policyFlags() *pflag.FlagSet {
	policyOnce.Do(func() {
		fs := pflag.NewFlagSet("policy", pflag.ContinueOnError)
		fs.BoolVar(&allowMutations, "allow-mutations", false, "also invoke tools that mutate but are not destructive")
		fs.BoolVar(&allowDestructive, "allow-destructive", false, "also invoke destructive and unannotated tools (dangerous)")
		fs.StringArrayVar(&onlyTools, "only", nil, "restrict execution to this tool (repeatable)")
		fs.StringArrayVar(&denyTools, "deny", nil, "never invoke this tool (repeatable)")
		fs.StringArrayVar(&toolArgs, "arg", nil, "argument override tool.field=value (repeatable); value parsed as JSON when possible")
		fs.BoolVar(&allowPrivateHosts, "insecure-allow-private-hosts", false, "allow discovered OAuth endpoints that resolve inside your network (off by default: a server naming one could aim your credentials at it)")
		fs.BoolVar(&allowPlaintextAuth, "insecure-allow-http-auth", false, "allow discovered OAuth endpoints served over plain http (off by default: tokens would cross the network in the clear)")
		fs.BoolVar(&allowResourceMismatch, "allow-resource-mismatch", false, "continue when the protected-resource metadata names a different endpoint (RFC 9728 requires this binding)")
		fs.BoolVar(&skipEraCheck, "skip-era-check", false, "do not send the one server/discover that identifies which protocol generation the server speaks")
		fs.StringVar(&policyFile, "policy", "", "judge the run against this acceptance policy file instead of the default \"any failure fails\" rule")
		fs.BoolVar(&watchEgress, "watch-egress", false, "run a loopback proxy and report where the server connects (stdio only: it works by setting the child's environment)")
		fs.StringArrayVar(&expectEgress, "expect-egress", nil, "a host the server is expected to reach (repeatable); a leading dot matches subdomains. Without it the destinations are listed and not judged")
		fs.BoolVar(&faultUpstream, "fault-upstream", false, "end the run by failing every connection the server makes and calling tools that succeeded, to see whether they fail or hang (stdio only; implies --watch-egress)")
		fs.BoolVar(&plantCanaries, "plant-canaries", false, "point the server's HOME at a scratch directory seeded with decoy credentials, and report whether it read or sent them (stdio only)")
		fs.StringVar(&clientConfigFile, "client-config", "", "an MCP client configuration (Claude Desktop, Cursor, VS Code or Zed): read its stdio launch commands, and compare this server's descriptions with the tools of the other servers it names, which are listed read-only")
		fs.StringVar(&baselineFile, "baseline", "", "compare the catalogue against this approved snapshot and report what changed")
		fs.BoolVar(&approveBaseline, "approve", false, "write the catalogue this run saw to the --baseline file, approving it")
		policySet = fs
	})
	return policySet
}

func paceFlags() *pflag.FlagSet {
	paceOnce.Do(func() {
		fs := pflag.NewFlagSet("pacing", pflag.ContinueOnError)
		fs.IntVar(&samples, "samples", 5, "repeat calls per tool in the performance phase")
		fs.IntVar(&concurrency, "concurrency", 4, "workers in the parallel burst (0 disables)")
		fs.Float64Var(&rps, "rps", 2, "max requests per second; 0 or negative disables throttling")
		fs.DurationVar(&callTimeout, "timeout", 30*time.Second, "per-call timeout")
		fs.StringVar(&userAgent, "user-agent", "", "User-Agent sent on every HTTP request, the unauthenticated first contact included (default: Go's)")
		fs.Uint64Var(&seed, "seed", 1, "seed for generated arguments")
		fs.BoolVar(&fillOpt, "fill-optional", false, "also populate optional schema properties")
		fs.BoolVar(&allowLoad, "allow-load", false, "run the burst unthrottled to test the server's rate limiting")
		fs.IntVar(&maxRes, "max-resources", 25, "max resources to read")
		fs.IntVar(&maxPrompts, "max-prompts", 25, "max prompts to render")
		fs.IntVar(&soak, "soak", 0, "after the run, call the fastest tool that succeeded this many more times and report the trend in the server's resident memory (stdio only, read on Linux; at least 100; paced by --rps)")
		paceSet = fs
	})
	return paceSet
}

func outputFlags() *pflag.FlagSet {
	outOnce.Do(func() {
		fs := pflag.NewFlagSet("output", pflag.ContinueOnError)
		fs.BoolVarP(&interactive, "interactive", "i", false, "pick the tools to exercise in an interactive selector before the run")
		fs.StringVar(&output, "output", "text", "output format: text, json, md, ndjson, html, sarif, junit, attestation, ocsf")
		fs.StringVar(&reportDir, "report-dir", "", "write report.{txt,md,json}, telemetry.ndjson and telemetry.har here")
		fs.StringVar(&retain, "retain", "", "with --report-dir, delete passmcp's own report files there older than this (a Go duration, or days as 30d), logging each on stderr")
		fs.BoolVar(&captureBodies, "capture-bodies", false, "record request/response bodies in telemetry (redacted, capped)")
		fs.BoolVar(&withEvents, "events", false, "embed every telemetry event in JSON output")
		fs.BoolVar(&withGuidance, "guidance", false, "embed remediation for each finding in JSON output, keyed by check id")
		fs.BoolVarP(&verbose, "verbose", "v", false, "show evidence references and full info findings")
		fs.BoolVar(&noColor, "no-color", false, "disable ANSI colour")
		fs.StringVar(&otlpEndpoint, "otlp-endpoint", "", "export the finished run as OpenTelemetry traces to this OTLP/HTTP collector")
		fs.StringArrayVar(&otlpHeaders, "otlp-header", nil, "extra header on the OTLP export, \"Name: value\" (repeatable)")
		fs.StringVar(&ocsfEndpoint, "ocsf-endpoint", "", "post the failing and warning findings as OCSF events to this endpoint (your SIEM); nothing is sent without it")
		fs.StringArrayVar(&ocsfHeaders, "ocsf-header", nil, "extra header on the OCSF post, \"Name: value\" (repeatable)")
		fs.StringSliceVar(&phasesOnly, "phases", nil, "run only these phases (comma-separated)")
		fs.StringSliceVar(&phasesSkip, "skip-phases", nil, "skip these phases (comma-separated)")
		outSet = fs
	})
	return outSet
}

// knownFlagNames lists every flag on any command, so a config key that
// belongs to a different command is not an error.
func knownFlagNames() map[string]bool {
	known := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) { known[f.Name] = true })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { known[f.Name] = true })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	return known
}

// buildSpec turns the parsed flags into the one value that configures a
// run. It is the only place package-level flag state is read: everything
// downstream takes the spec, which is what lets the TUI and the web UI
// drive exactly the run the CLI would have.
func buildSpec(target engine.TargetSpec, onlyPhases []string) (engine.RunSpec, error) {
	retainFor, err := engine.ParseRetention(retain)
	if err != nil {
		return engine.RunSpec{}, err
	}
	overrides, err := parseToolArgs(toolArgs)
	if err != nil {
		return engine.RunSpec{}, err
	}
	cs, err := credSpec()
	if err != nil {
		return engine.RunSpec{}, err
	}
	phases := phasesOnly
	if len(onlyPhases) > 0 {
		phases = onlyPhases
	}

	// The file is read here, in the surface, and the loaded policy goes into
	// the spec. A path in the spec would ask whichever process received it
	// to open a file somebody else named, which is a different and much
	// worse thing for the web surface to accept.
	approved, err := loadBaseline()
	if err != nil {
		return engine.RunSpec{}, err
	}
	clients, err := loadClientConfig()
	if err != nil {
		return engine.RunSpec{}, err
	}

	var gate *policy.Policy
	if strings.TrimSpace(policyFile) != "" {
		p, err := policy.Load(policyFile)
		if err != nil {
			return engine.RunSpec{}, err
		}
		gate = p
	}

	target.UserAgent = userAgent
	spec := engine.RunSpec{
		Version:      Version,
		Target:       target,
		Baseline:     approved,
		ClientConfig: clients,
		Egress:       engine.EgressSpec{Watch: watchEgress || faultUpstream, Expect: expectEgress, Canaries: plantCanaries, FaultUpstream: faultUpstream},
		Creds:        cs,
		Policy: engine.PolicySpec{
			AllowMutations: allowMutations, AllowDestructive: allowDestructive,
			Only: onlyTools, Deny: denyTools, ToolArgs: overrides,
			AllowPlaintextAuth: allowPlaintextAuth, AllowPrivateHosts: allowPrivateHosts,
			AllowResourceMismatch: allowResourceMismatch, SkipEraCheck: skipEraCheck,
		},
		Gate: gate,
		Pacing: engine.PacingSpec{
			Samples: samples, Concurrency: concurrency, RPS: rps,
			CallTimeout: callTimeout, Seed: seed, FillOptional: fillOpt,
			AllowLoad: allowLoad, MaxResources: maxRes, MaxPrompts: maxPrompts,
			Soak: soak,
		},
		Phases: engine.PhaseSpec{Only: phases, Skip: phasesSkip},
		Output: engine.OutputSpec{
			Format: engine.Format(output), ReportDir: reportDir, Retain: retainFor,
			CaptureBodies: captureBodies, WithEvents: withEvents, WithGuidance: withGuidance,
			Verbose: verbose, NoColor: noColor, Interactive: interactive,
			OTLPEndpoint: otlpEndpoint, OTLPHeaders: otlpHeaders,
			OCSFEndpoint: ocsfEndpoint, OCSFHeaders: ocsfHeaders,
		},
	}
	return spec.WithDefaults(), nil
}

// credSpec is the credential half of the spec, from the credential flags.
func credSpec() (engine.CredSpec, error) {
	hdrs := map[string]string{}
	for _, h := range headers {
		k, v, err := creds.ParseHeader(h)
		if err != nil {
			return engine.CredSpec{}, err
		}
		hdrs[k] = v
	}
	prm := url.Values{}
	for _, p := range params {
		k, v, err := creds.ParseParam(p)
		if err != nil {
			return engine.CredSpec{}, err
		}
		prm.Add(k, v)
	}
	return engine.CredSpec{
		Mode: authMode, Token: token, TokenEnv: tokenEnv,
		Headers: hdrs, Basic: basic,
		ClientID: clientID, ClientSecret: clientSecret, ClientSecretEnv: clientSecretEnv,
		ClientMetadataURL: clientMetadataURL, Scope: scope, Params: prm,
		TokenURL: tokenURL, AuthURL: authURL, Resource: resource,
		RedirectPort: redirectPort, TokenAuthMethod: tokenAuthMethod,
		WrongAudienceTokenEnv: wrongAudienceTokenEnv,
	}, nil
}

// buildCreds turns the credential flags and environment into a model.
func buildCreds() (*creds.Credentials, error) {
	c := &creds.Credentials{Mode: creds.Mode(authMode), Headers: map[string]string{}, Params: url.Values{}, Sources: map[string]string{}}
	c.SetFromFlag("token", token)
	c.SetFromFlag("client-id", clientID)
	c.SetFromFlag("client-secret", clientSecret)
	c.SetFromFlag("basic", basic)
	if err := c.SetFromEnvName("token", tokenEnv); err != nil {
		return nil, err
	}
	if err := c.SetFromEnvName("client-secret", clientSecretEnv); err != nil {
		return nil, err
	}
	c.FromEnv()
	for _, h := range headers {
		k, v, err := creds.ParseHeader(h)
		if err != nil {
			return nil, err
		}
		c.Headers[k] = v
		c.Sources["header "+k] = "flag --header"
	}
	for _, p := range params {
		k, v, err := creds.ParseParam(p)
		if err != nil {
			return nil, err
		}
		c.Params.Add(k, v)
	}
	c.ClientMetadataURL, c.Scope, c.TokenURL, c.AuthURL, c.Resource = clientMetadataURL, scope, tokenURL, authURL, resource
	c.RedirectPort, c.TokenAuthMethod = redirectPort, tokenAuthMethod
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func buildPolicy() diagnostics.Policy {
	return diagnostics.Policy{AllowMutations: allowMutations, AllowDestructive: allowDestructive, Only: onlyTools, Deny: denyTools}
}

// parseToolArgs turns --arg tool.field=value into per-tool overrides. A
// value that parses as JSON is used as such, otherwise as a string.
func parseToolArgs(items []string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	for _, it := range items {
		key, val, ok := strings.Cut(it, "=")
		if !ok {
			return nil, fmt.Errorf("--arg %q must be tool.field=value", it)
		}
		tool, field, ok := strings.Cut(key, ".")
		if !ok || tool == "" || field == "" {
			return nil, fmt.Errorf("--arg %q must be tool.field=value", it)
		}
		if out[tool] == nil {
			out[tool] = map[string]any{}
		}
		out[tool][field] = jsonOrString(val)
	}
	return out, nil
}

func validOutput(o string) bool { return engine.Format(o).Valid() }

// splitAtDash separates passmcp's own arguments from the server's.
//
// Everything after "--" belongs to the program being run. That is what lets
// a server have its own flags without passmcp guessing whose they are, and it
// is why there is no single-string form: splitting a command string means
// quoting rules, and quoting rules mean a shell.
func splitAtDash(cmd *cobra.Command, args []string) (before, after []string) {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 || dash > len(args) {
		return args, nil
	}
	return args[:dash], args[dash:]
}

// stdioTarget builds a target from the words after "--".
func stdioTarget(after []string) (engine.TargetSpec, error) {
	if len(after) == 0 {
		return engine.TargetSpec{}, fmt.Errorf("--stdio needs the command to run, after --, for example:\n\n" +
			"    passmcp check --stdio -- npx -y @modelcontextprotocol/server-everything")
	}
	t := engine.TargetSpec{Command: after[0], Args: after[1:], Dir: stdioDir, PassEnv: stdioEnv}
	if len(stdioOnly) > 0 {
		// An explicit set replaces everything, including the base that lets
		// a program find its interpreter. That is the point of asking for it
		// by name: the operator is saying "exactly this".
		for _, kv := range stdioOnly {
			if !strings.Contains(kv, "=") {
				return engine.TargetSpec{}, fmt.Errorf("--stdio-set takes NAME=value; %q has no value. "+
					"To forward a variable that is already set, use --stdio-env %s", kv, kv)
			}
		}
		t.Env = append([]string{}, stdioOnly...)
	}
	return t, nil
}

// resolveTarget decides what this run is pointed at: a URL, or a program.
//
// The two are exclusive and the error says so rather than picking one. A
// run that silently ignored the endpoint because --stdio was also passed
// would produce a report about a different server than the one named on the
// command line, and nothing in that report would reveal it.
func resolveTarget(cmd *cobra.Command, args []string) (engine.TargetSpec, error) {
	before, after := splitAtDash(cmd, args)
	if !useStdio {
		if len(after) > 0 {
			return engine.TargetSpec{}, fmt.Errorf("arguments after -- describe a program to run; pass --stdio to run one")
		}
		endpoint, err := resolveEndpoint(before)
		if err != nil {
			return engine.TargetSpec{}, err
		}
		return engine.TargetSpec{Endpoint: endpoint}, nil
	}
	if len(before) > 0 {
		return engine.TargetSpec{}, fmt.Errorf("--stdio runs a program, so %q is not an endpoint to also check; a run has one target", before[0])
	}
	return stdioTarget(after)
}

// callTarget resolves `passmcp call`'s two operands, which differ by
// transport: an endpoint and a tool over HTTP, a tool and a command after
// "--" over stdio.
func callTarget(cmd *cobra.Command, args []string) (engine.TargetSpec, string, error) {
	before, after := splitAtDash(cmd, args)
	if useStdio {
		if len(before) != 1 {
			return engine.TargetSpec{}, "", fmt.Errorf("with --stdio, name the tool before -- and the server after it:\n\n" +
				"    passmcp call --stdio <tool> -- <command> [args...]")
		}
		t, err := stdioTarget(after)
		if err != nil {
			return engine.TargetSpec{}, "", err
		}
		return t, before[0], nil
	}
	if len(after) > 0 {
		return engine.TargetSpec{}, "", fmt.Errorf("arguments after -- describe a program to run; pass --stdio to run one")
	}
	if len(before) != 2 {
		return engine.TargetSpec{}, "", fmt.Errorf("usage: passmcp call <endpoint> <tool>, or passmcp call --stdio <tool> -- <command>")
	}
	return engine.TargetSpec{Endpoint: before[0]}, before[1], nil
}

// loadBaseline reads the approved baseline named by --baseline.
//
// Read here for the same reason the policy file is: the surface opens
// files, the spec carries values. An absent baseline with --approve is
// the first approval rather than an error, so a missing file is not
// one.
func loadBaseline() (*baseline.Snapshot, error) {
	if approveBaseline && strings.TrimSpace(baselineFile) == "" {
		return nil, errors.New("--approve needs --baseline: there is no file to write")
	}
	if strings.TrimSpace(baselineFile) == "" {
		return nil, nil
	}
	snap, err := baseline.Load(baselineFile)
	switch {
	case err == nil:
		return snap, nil
	case approveBaseline && errors.Is(err, os.ErrNotExist):
		// Approving into a path that does not exist yet.
		return nil, nil
	default:
		return nil, err
	}
}

// loadClientConfig reads the file named by --client-config, for the same
// reason: the surface reads the file and the spec carries what it says.
func loadClientConfig() (*clientconf.Config, error) {
	if strings.TrimSpace(clientConfigFile) == "" {
		return nil, nil
	}
	return clientconf.Load(clientConfigFile)
}
