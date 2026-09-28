// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package engine is the one place a passmcp run is configured and started.
//
// Every surface — the CLI, the TUI, and the web UI — builds a RunSpec and
// calls Run. Nothing else configures a run, and no capability lives in a
// surface rather than under it: the moment one does, the surfaces are no
// longer peers and no amount of front-end work brings that back.
package engine

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/clientconf"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/policy"
	"satellion.com/passmcp/internal/probe"
)

// RunSpec is the whole of a run's intent, in one serialisable value.
//
// It round-trips through JSON so the web UI can post exactly what the CLI
// would have assembled from flags. Secrets are the one exception: fields
// holding a credential value are marked json:"-" so a spec that crosses a
// network carries references to credentials, never the credentials. A
// surface that needs to supply a secret directly does it in-process.
type RunSpec struct {
	// Target is the MCP server under test.
	Target TargetSpec `json:"target"`
	// Creds says how to authenticate, by reference where it can.
	Creds CredSpec `json:"credentials"`
	// Policy decides which tools may be invoked.
	Policy PolicySpec `json:"policy"`
	// Gate is the acceptance policy the finished run is judged against, or
	// nil to judge it by the default rule (any failing finding fails the
	// run).
	//
	// Named Gate rather than Policy because PolicySpec above already means
	// something narrower and older: what passmcp is allowed to do to the
	// server. This is what the operator is willing to accept back. The
	// user-facing flag is --policy, because that is what the file is.
	//
	// It carries the policy itself rather than a path, so a spec that
	// crosses a network never asks the receiving process to read a file
	// somebody else named.
	Gate *policy.Policy `json:"gate,omitempty"`
	// Egress asks the run to watch where the server connects.
	Egress EgressSpec `json:"egress,omitempty"`
	// Baseline is the approved catalogue this run is judged against, or
	// nil to judge nothing.
	//
	// Carried by value for the reason Gate is: a spec that crosses a
	// network must never ask the receiving process to read a file
	// somebody else named. The surface reads the file; the engine reads
	// the spec.
	Baseline *baseline.Snapshot `json:"baseline,omitempty"`
	// ClientConfig is the MCP client configuration the server is used in:
	// the other servers an agent has beside it, and how each stdio server is
	// started. Carried by value for the reason Baseline is; its env and
	// header values never serialise, only their names.
	ClientConfig *clientconf.Config `json:"client_config,omitempty"`
	// Pacing bounds how hard the server is exercised.
	Pacing PacingSpec `json:"pacing"`
	// Phases selects which parts of the diagnostic run.
	Phases PhaseSpec `json:"phases"`
	// Output says what to produce and where to put it.
	Output OutputSpec `json:"output"`
	// Version is the passmcp build identifier recorded in the report.
	Version string `json:"version,omitempty"`
}

// TargetSpec identifies the server under test: either a URL to talk to or
// a program to run.
type TargetSpec struct {
	// Endpoint is the Streamable HTTP URL.
	Endpoint string `json:"endpoint"`
	// UserAgent, when set, is sent on every HTTP request of the run,
	// including the unauthenticated first contact on the bare transport.
	// Empty leaves Go's default. A job that publishes its identity (the
	// registry scorecard's published User-Agent) sets it; nothing else
	// needs to.
	UserAgent string `json:"user_agent,omitempty"`
	// Command is the program to run as the server, with Args, when the
	// server speaks over stdio. Exactly one of Endpoint and Command is set.
	//
	// It is not a shell command: nothing is expanded, split or quoted, and
	// a pipe in it is a pipe in the program's name. That is deliberate —
	// this value arrives from a CLI flag today and could arrive from a web
	// client tomorrow, and "run this string through a shell" is not a
	// capability to leave lying in the request path.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Dir is the working directory for the server; empty means passmcp's.
	Dir string `json:"dir,omitempty"`
	// PassEnv names environment variables to forward to the server.
	//
	// Only these, plus a fixed base that lets a program find its
	// interpreter, reach the child. A server passmcp is diagnosing is a
	// program nobody has audited, and handing it every exported variable
	// is how a credential for something else ends up inside it.
	PassEnv []string `json:"pass_env,omitempty"`
	// Env, when non-nil, replaces the child's environment entirely.
	// Excluded from JSON: a variable's value is as sensitive as a token,
	// and a spec that crosses a boundary carries names, not values.
	Env []string `json:"-"`
}

// Stdio reports whether the target is a program rather than a URL.
func (t TargetSpec) Stdio() bool { return strings.TrimSpace(t.Command) != "" }

// Describe names the target for a human: the URL, or the command line.
func (t TargetSpec) Describe() string {
	if t.Stdio() {
		return strings.Join(append([]string{t.Command}, t.Args...), " ")
	}
	return t.Endpoint
}

// CredSpec mirrors the credential surface. Fields that hold a secret
// value are excluded from JSON; the *Env fields name an environment
// variable to read instead, which is how a spec crossing a process or a
// network boundary carries credentials safely.
type CredSpec struct {
	Mode string `json:"mode,omitempty"`

	Token    string `json:"-"`
	TokenEnv string `json:"token_env,omitempty"`

	// Headers are sent verbatim (API keys, tenant selectors). Excluded
	// from JSON because an API key is as sensitive as a token.
	Headers map[string]string `json:"-"`
	// Basic is user:password.
	Basic string `json:"-"`

	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"-"`
	ClientSecretEnv string `json:"client_secret_env,omitempty"`

	ClientMetadataURL string     `json:"client_metadata_url,omitempty"`
	Scope             string     `json:"scope,omitempty"`
	Params            url.Values `json:"params,omitempty"`
	TokenURL          string     `json:"token_url,omitempty"`
	AuthURL           string     `json:"auth_url,omitempty"`
	Resource          string     `json:"resource,omitempty"`
	RedirectPort      int        `json:"redirect_port,omitempty"`
	TokenAuthMethod   string     `json:"token_auth_method,omitempty"`

	// WrongAudienceTokenEnv names a variable holding a token the operator's
	// authorization server issued for a different resource, which
	// auth.wrong_audience sends. The value itself never serialises.
	WrongAudienceToken    string `json:"-"`
	WrongAudienceTokenEnv string `json:"wrong_audience_token_env,omitempty"`
}

// PolicySpec decides what may be invoked, and which discovered endpoints
// passmcp is willing to talk to.
type PolicySpec struct {
	AllowMutations   bool     `json:"allow_mutations,omitempty"`
	AllowDestructive bool     `json:"allow_destructive,omitempty"`
	Only             []string `json:"only,omitempty"`
	Deny             []string `json:"deny,omitempty"`
	// ToolArgs overrides generated arguments, keyed by tool then field.
	ToolArgs map[string]map[string]any `json:"tool_args,omitempty"`

	// The three insecure_* fields each switch off a check that exists
	// because everything past the operator's own endpoint is chosen by the
	// server under test.
	AllowPlaintextAuth    bool `json:"insecure_allow_http_auth,omitempty"`
	AllowPrivateHosts     bool `json:"insecure_allow_private_hosts,omitempty"`
	AllowResourceMismatch bool `json:"allow_resource_mismatch,omitempty"`
	SkipEraCheck          bool `json:"skip_era_check,omitempty"`
}

// PacingSpec bounds the load a run places on the server.
type PacingSpec struct {
	Samples      int           `json:"samples,omitempty"`
	Concurrency  int           `json:"concurrency,omitempty"`
	RPS          float64       `json:"rps"`
	CallTimeout  time.Duration `json:"call_timeout_ns,omitempty"`
	Seed         uint64        `json:"seed,omitempty"`
	FillOptional bool          `json:"fill_optional,omitempty"`
	AllowLoad    bool          `json:"allow_load,omitempty"`
	MaxResources int           `json:"max_resources,omitempty"`
	MaxPrompts   int           `json:"max_prompts,omitempty"`
	// Soak repeats the fastest successful tool call this many more times
	// after the run and reports the trend in the server's resident memory.
	// Zero is off. It needs a program to run, since the memory read is of
	// a process passmcp started, and at least probe.SoakMinCalls calls for a
	// trend to mean anything.
	Soak int `json:"soak,omitempty"`
}

// EgressSpec says whether to watch a server's outbound connections, and
// what to measure them against.
//
// Only meaningful for a stdio target: an endpoint passmcp did not start has
// an environment passmcp never set, so there is no proxy to point it at.
type EgressSpec struct {
	// Watch runs the loopback proxy and points the child at it.
	Watch bool `json:"watch,omitempty"`
	// Expect is the hosts the operator says the server should reach. A
	// leading dot matches subdomains. Empty inventories without judging.
	Expect []string `json:"expect,omitempty"`
	// FaultUpstream fails the server's outbound connections at the end of
	// the run and checks that tool calls still come back. Needs Watch.
	FaultUpstream bool `json:"fault_upstream,omitempty"`
	// Canaries points the child's HOME at a scratch directory seeded with
	// decoy credentials, so a server that goes looking can be seen.
	Canaries bool `json:"canaries,omitempty"`
}

// PhaseSpec selects phases by name.
type PhaseSpec struct {
	Only []string `json:"only,omitempty"`
	Skip []string `json:"skip,omitempty"`
}

// Format is an output rendering.
type Format string

// The formats a report can be rendered as.
const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	FormatMD     Format = "md"
	FormatNDJSON Format = "ndjson"
	// FormatHTML is one self-contained document: the file somebody opens
	// offline, the page passmcp serve shows, and — through its print
	// stylesheet — the PDF a board reads.
	FormatHTML Format = "html"
	// FormatSARIF and FormatJUnit exist so a run reaches the place a team
	// already looks: code scanning for one, the test panel for the other.
	// Neither is a richer report than JSON; both are the same findings in
	// the shape a specific reader will not accept a substitute for.
	FormatSARIF Format = "sarif"
	FormatJUnit Format = "junit"
	// FormatAttestation is not a report. Every other format here is the
	// findings arranged for a particular reader; this one is a claim about
	// the server, in the in-toto envelope a supply-chain pipeline already
	// verifies, and it is meant to be signed and handed to a machine that
	// was not present when the run happened. `passmcp verify` is the other
	// half of it.
	FormatAttestation Format = "attestation"
	// FormatOCSF is the failing and warning findings as OCSF 1.3 events, for a
	// SIEM: Vulnerability Finding or Compliance Finding, one per finding.
	FormatOCSF Format = "ocsf"
)

// Formats lists every valid output format.
var Formats = []Format{FormatText, FormatJSON, FormatMD, FormatNDJSON, FormatHTML, FormatSARIF, FormatJUnit, FormatAttestation, FormatOCSF}

// Valid reports whether f is a format passmcp can render.
func (f Format) Valid() bool {
	for _, v := range Formats {
		if f == v {
			return true
		}
	}
	return false
}

// OutputSpec says what to produce.
type OutputSpec struct {
	Format Format `json:"format,omitempty"`
	// ReportDir, when set, receives report.{txt,md,json} plus telemetry.
	ReportDir string `json:"report_dir,omitempty"`
	// Retain, when positive, is how long passmcp's own files in ReportDir
	// are kept: older ones are deleted before the run writes its own, and
	// each deletion is logged. Storage limitation (GDPR Art. 5(1)(e)) for
	// a directory a scheduled run writes to again and again.
	Retain time.Duration `json:"retain_ns,omitempty"`
	// CaptureBodies records request and response bodies, redacted and
	// capped, in the telemetry.
	CaptureBodies bool `json:"capture_bodies,omitempty"`
	// WithEvents embeds every telemetry event in the JSON report.
	WithEvents bool `json:"with_events,omitempty"`
	// WithGuidance embeds the remediation for each check that produced a
	// finding, as a dictionary keyed by check id. Off by default because
	// most consumers have doc_url and want the report small; on for the
	// ones that have to explain a finding somewhere passmcp cannot reach,
	// like a bot writing a pull request comment.
	WithGuidance bool `json:"with_guidance,omitempty"`
	// Verbose shows evidence references and info findings.
	Verbose bool `json:"verbose,omitempty"`
	// NoColor disables ANSI colour in the text rendering.
	NoColor bool `json:"no_color,omitempty"`
	// Interactive asks the surface to choose tools before the run. The
	// chosen names land in Policy.Only, so a run is reproducible from the
	// spec afterwards without asking again.
	Interactive bool `json:"interactive,omitempty"`
	// OTLPEndpoint, when set, receives the finished run as OpenTelemetry
	// traces. Export happens after the report is rendered and never
	// changes the exit code: a collector being down is not a finding
	// about the server under test.
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
	// OTLPHeaders are extra headers on the export request, "Name: value",
	// for a collector that wants an API key or a tenant id.
	OTLPHeaders []string `json:"otlp_headers,omitempty"`
	// OCSFEndpoint is where the run's OCSF events are posted, when the
	// operator named one. Empty means they go nowhere.
	OCSFEndpoint string `json:"ocsf_endpoint,omitempty"`
	// OCSFHeaders are extra "Name: value" headers on that post, typically
	// the collector's token. Never serialised: a plan must not carry it.
	OCSFHeaders []string `json:"-"`
}

// Defaults are the values a run takes when a spec leaves them unset. They
// live here rather than in flag definitions so every surface gets the same
// ones, including a web client that sent a half-filled spec.
const (
	DefaultSamples      = 5
	DefaultConcurrency  = 4
	DefaultRPS          = 2
	DefaultCallTimeout  = 30 * time.Second
	DefaultSeed         = 1
	DefaultMaxResources = 25
	DefaultMaxPrompts   = 25
	DefaultRedirectPort = 8976
)

// WithDefaults returns a copy of s with unset values filled in.
func (s RunSpec) WithDefaults() RunSpec {
	if s.Creds.Mode == "" {
		s.Creds.Mode = string(creds.ModeAuto)
	}
	if s.Creds.RedirectPort == 0 {
		s.Creds.RedirectPort = DefaultRedirectPort
	}
	if s.Pacing.Samples == 0 {
		s.Pacing.Samples = DefaultSamples
	}
	if s.Pacing.Concurrency == 0 {
		s.Pacing.Concurrency = DefaultConcurrency
	}
	if s.Pacing.CallTimeout == 0 {
		s.Pacing.CallTimeout = DefaultCallTimeout
	}
	if s.Pacing.Seed == 0 {
		s.Pacing.Seed = DefaultSeed
	}
	if s.Pacing.MaxResources == 0 {
		s.Pacing.MaxResources = DefaultMaxResources
	}
	if s.Pacing.MaxPrompts == 0 {
		s.Pacing.MaxPrompts = DefaultMaxPrompts
	}
	if s.Output.Format == "" {
		s.Output.Format = FormatText
	}
	return s
}

// Validate reports why a spec cannot be run. It is the same check for
// every surface, so a web client gets the CLI's error rather than a
// different one.
func (s RunSpec) Validate() error {
	if err := s.validateTarget(); err != nil {
		return err
	}
	if err := s.validateStdioOnly(); err != nil {
		return err
	}
	if err := s.validateHTTPOnly(); err != nil {
		return err
	}
	if !s.Output.Format.Valid() {
		return fmt.Errorf("output format %q is not one of %v", s.Output.Format, Formats)
	}
	if s.Gate != nil {
		if err := s.Gate.Validate(); err != nil {
			return err
		}
	}
	for _, name := range append(append([]string{}, s.Phases.Only...), s.Phases.Skip...) {
		if !knownPhase(name) {
			return fmt.Errorf("unknown phase %q; known phases are %s", name, strings.Join(probe.PhaseNames(), ", "))
		}
	}
	c, err := s.Credentials()
	if err != nil {
		return err
	}
	if s.Target.Stdio() && c.Effective() != creds.ModeNone {
		return fmt.Errorf("credentials have no meaning over stdio: a child process has no origin to authorize against, "+
			"and %s would be sent nowhere. Pass what the server needs in its arguments, or forward a variable with --stdio-env", c.Effective())
	}
	return nil
}

// validateTarget checks that the spec names exactly one target, and that an
// endpoint is an absolute URL.
func (s RunSpec) validateTarget() error {
	switch {
	case s.Target.Stdio() && strings.TrimSpace(s.Target.Endpoint) != "":
		return errors.New("a run has one target: an endpoint or a command, not both")
	case s.Target.Stdio():
		// Nothing further to validate about a command here. Whether the
		// program exists is answered by trying to run it, and the error
		// from exec names the path better than a guess from a stat would.
	case strings.TrimSpace(s.Target.Endpoint) == "":
		return errors.New("an endpoint is required")
	default:
		u, err := url.Parse(s.Target.Endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("endpoint %q is not an absolute URL", s.Target.Endpoint)
		}
	}
	return nil
}

// validateStdioOnly refuses the options that only mean something for a
// process passmcp started, and a soak too short to measure.
func (s RunSpec) validateStdioOnly() error {
	if s.Egress.FaultUpstream && !s.Target.Stdio() {
		// Asked for and silently not done would read as a server that
		// survives its dependencies failing.
		return errors.New("--fault-upstream fails a server's connections through a proxy it is started with, so it needs a program to run (--stdio); an endpoint passmcp did not start cannot be pointed at one")
	}
	if s.Pacing.Soak > 0 && !s.Target.Stdio() {
		return errors.New("--soak reads the resident memory of a process passmcp started, so it needs a program to run (--stdio); an endpoint's memory is not passmcp's to read")
	}
	if s.Pacing.Soak > 0 && s.Pacing.Soak < probe.SoakMinCalls {
		return fmt.Errorf("--soak %d is too short to fit a trend through; ask for at least %d calls", s.Pacing.Soak, probe.SoakMinCalls)
	}
	return nil
}

// validateHTTPOnly refuses the options that only mean something for an
// endpoint passmcp authenticates to.
func (s RunSpec) validateHTTPOnly() error {
	if s.Target.Stdio() && (s.Creds.WrongAudienceToken != "" || s.Creds.WrongAudienceTokenEnv != "") {
		// Asked for and silently not done would read as a server that
		// checks the audience of its tokens.
		return errors.New("--wrong-audience-token-env sends a token to an endpoint's authorization check, and a program started over stdio has none; it needs an endpoint URL")
	}
	return nil
}

func knownPhase(name string) bool {
	for _, p := range probe.PhaseNames() {
		if p == name {
			return true
		}
	}
	return false
}

// credentials turns the spec's credential half into the resolved model,
// reading any environment variables it names.
func (s RunSpec) credentials() *creds.Credentials {
	c := &creds.Credentials{
		Mode:    creds.Mode(s.Creds.Mode),
		Headers: map[string]string{},
		Params:  url.Values{},
		Sources: map[string]string{},
	}
	c.SetFromFlag("token", s.Creds.Token)
	c.SetFromFlag("client-id", s.Creds.ClientID)
	c.SetFromFlag("client-secret", s.Creds.ClientSecret)
	c.SetFromFlag("basic", s.Creds.Basic)
	// An environment reference that names a missing variable is an error,
	// but Validate reports it; resolution here is best-effort so the
	// caller sees one error rather than two.
	_ = c.SetFromEnvName("token", s.Creds.TokenEnv)
	_ = c.SetFromEnvName("client-secret", s.Creds.ClientSecretEnv)
	c.SetFromFlag("wrong-audience-token", s.Creds.WrongAudienceToken)
	_ = c.SetFromEnvName("wrong-audience-token", s.Creds.WrongAudienceTokenEnv)
	c.FromEnv()
	for k, v := range s.Creds.Headers {
		c.Headers[k] = v
		c.Sources["header "+k] = "spec"
	}
	for k, vs := range s.Creds.Params {
		for _, v := range vs {
			c.Params.Add(k, v)
		}
	}
	c.ClientMetadataURL = s.Creds.ClientMetadataURL
	c.Scope = s.Creds.Scope
	c.TokenURL = s.Creds.TokenURL
	c.AuthURL = s.Creds.AuthURL
	c.Resource = s.Creds.Resource
	c.RedirectPort = s.Creds.RedirectPort
	c.TokenAuthMethod = s.Creds.TokenAuthMethod
	return c
}

// Credentials resolves the spec's credentials, reporting a named
// environment variable that is not set.
func (s RunSpec) Credentials() (*creds.Credentials, error) {
	c := s.credentials()
	if err := c.SetFromEnvName("token", s.Creds.TokenEnv); err != nil {
		return nil, err
	}
	if err := c.SetFromEnvName("client-secret", s.Creds.ClientSecretEnv); err != nil {
		return nil, err
	}
	if err := c.SetFromEnvName("wrong-audience-token", s.Creds.WrongAudienceTokenEnv); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// diagnosticsPolicy is the tool-invocation half of the policy.
func (s RunSpec) diagnosticsPolicy() diagnostics.Policy {
	return diagnostics.Policy{
		AllowMutations:   s.Policy.AllowMutations,
		AllowDestructive: s.Policy.AllowDestructive,
		Only:             s.Policy.Only,
		Deny:             s.Policy.Deny,
	}
}

// urlPolicy is the discovered-endpoint half.
func (s RunSpec) urlPolicy() auth.URLPolicy {
	return auth.URLPolicy{
		AllowHTTP:    s.Policy.AllowPlaintextAuth,
		AllowPrivate: s.Policy.AllowPrivateHosts,
	}
}
