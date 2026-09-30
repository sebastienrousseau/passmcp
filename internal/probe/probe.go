// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package probe runs passmcp's step-by-step diagnostic against one MCP
// server. Each phase makes real requests, records what it observed, and
// emits findings with evidence; nothing is reported as passing without a
// request that showed it.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/canary"
	"satellion.com/passmcp/internal/clientconf"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/egress"
	"satellion.com/passmcp/internal/supply"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/internal/witness"
	"satellion.com/passmcp/spec/controls"
	"satellion.com/passmcp/trace"
	"satellion.com/passmcp/transport"
)

// Status of a finding or phase.
type Status string

// Finding statuses. Pass needs a request that showed the property; Info is
// an observation with no judgement; Warn is a deviation an agent can live
// with; Fail is one it cannot; Skip means the check did not run.
const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
	Info Status = "info"
)

// Severity of a failed or warned finding.
type Severity string

// Severities drive the score: Critical zeroes a category, Major costs 40,
// Minor 15. Note carries no deduction.
const (
	Critical Severity = "critical"
	Major    Severity = "major"
	Minor    Severity = "minor"
	Note     Severity = "info"
)

// Finding is one observed fact about the server.
type Finding struct {
	ID       string   `json:"id"`
	Phase    string   `json:"phase"`
	Title    string   `json:"title"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Advice   string   `json:"advice,omitempty"`
	// DocURL addresses this check in the published inventory. A report
	// read six months after the run is the normal case, not the edge one,
	// and "protocol.malformed_json" is only self-explanatory to somebody
	// who already knows what it means.
	DocURL   string `json:"doc_url,omitempty"`
	Duration Millis `json:"duration_ms,omitempty"`
	// Controls are the SOC 2 criteria, ISO/IEC 27001:2022 Annex A controls
	// and GDPR articles this check evidences, from the published mapping in
	// spec/controls. Every framework is present as a list, empty when the
	// check evidences nothing there, so a consumer never has to tell a
	// missing field from an empty one.
	Controls controls.Set `json:"controls"`
}

// DocBase is where the generated check inventory is published.
const DocBase = "https://satellion.com/passmcp/docs/checks/"

// DocURL addresses id in the published inventory.
//
// The fragment must match the anchor scripts/checkinventory writes into
// each table row; checks_doc_test.go fails the build when they diverge, so
// a link that ships in every report cannot quietly rot.
//
// A computed family id — auth.source.<field> — is addressed by its family
// rather than by the value, because the inventory documents the family and
// the value is whatever this particular server happened to have.
func DocURL(id string) string {
	if id == "" {
		return ""
	}
	for _, f := range DocFamilies {
		if strings.HasPrefix(id, f) {
			id = strings.TrimSuffix(f, ".")
			break
		}
	}
	return DocBase + "#check-" + strings.ReplaceAll(id, ".", "-")
}

// DocFamilies lists the checks whose id is built at run time, as the
// literal prefix everything after it is a value of.
//
// A family gets one row in the inventory, so every instance has to resolve
// to that row. checks_doc_test.go fails the build when the inventory grows
// a family this list does not know about — which is the only way a new
// family could ship with a dead link in every report that contains it.
var DocFamilies = []string{"auth.source."}

// PhaseResult groups the findings of one phase.
type PhaseResult struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	// Started is when the phase began. The loop already measured it to
	// compute Duration and threw it away; a trace exporter needs the
	// absolute instant, and laying phases end to end from the run's start
	// would be a guess dressed as a measurement.
	Started  time.Time `json:"started"`
	Duration Millis    `json:"duration_ms"`
	Skipped  string    `json:"skipped,omitempty"`
	// Summary is the one-line, plain-language outcome of the phase.
	Summary  string    `json:"summary,omitempty"`
	Findings []Finding `json:"findings"`
}

// Options configures a run.
type Options struct {
	Endpoint string
	// UserAgent, when set, replaces Go's default User-Agent on every HTTP
	// request: the client's, the bare transport's first contact and the
	// discovery of the authorization server. Empty changes nothing.
	UserAgent string
	// Stdio, when set, runs the server as a child process and speaks to it
	// over its pipes. Endpoint must be empty.
	//
	// Most MCP servers are programs rather than endpoints, so this is not
	// an alternative mode so much as the common one. What it costs is that
	// the phases which are about HTTP — reachability, authorization,
	// header conformance — have no subject, and each says so by name
	// rather than being left out of the report.
	Stdio      *passmcp.StdioConfig
	Creds      *creds.Credentials
	Store      *creds.Store
	Recorder   *telemetry.Recorder
	HTTPClient *http.Client // base client; its Transport is wrapped by the recorder
	// Dial, when HTTPClient has no Transport of its own, makes the run's TCP
	// connections. Nil means a plain net.Dialer; tests use it to stand in
	// for DNS and the network.
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Version string

	Policy diagnostics.Policy
	// URLPolicy governs which discovered OAuth endpoints may be fetched or
	// sent credentials. The zero value is strict.
	URLPolicy auth.URLPolicy
	// AllowResourceMismatch continues past a protected-resource document
	// that does not name this endpoint.
	AllowResourceMismatch bool
	// SkipEraCheck suppresses the single server/discover that identifies
	// which generation of the protocol the server speaks. It exists because
	// that probe is a request reaching the server under test, and this
	// project treats an unavoidable new request as a breaking change.
	SkipEraCheck bool
	Samples      int
	Concurrency  int
	RPS          float64
	CallTimeout  time.Duration
	Seed         uint64
	FillOptional bool
	AllowLoad    bool
	MaxResources int
	MaxPrompts   int
	// Soak is how many more times to call the fastest tool that succeeded,
	// after the run, reading the server's resident memory after each. Zero
	// is off. Stdio only, because the memory read is of the process passmcp
	// started, and it goes through the same throttle as every other call.
	Soak int
	// ToolArgs overrides generated arguments per tool.
	ToolArgs map[string]map[string]any
	// WatchEgress runs a loopback proxy and points the child at it, so
	// the run can report where the server connected.
	//
	// Only meaningful over stdio: an endpoint passmcp did not start has an
	// environment passmcp never set. Off by default, because it changes the
	// environment the server runs in and that is not something to do to
	// somebody's server without being asked.
	WatchEgress bool
	// ExpectEgress is the hosts the operator says the server should
	// reach. A leading dot matches subdomains. Empty means the
	// destinations are inventoried and not judged.
	ExpectEgress []string
	// FaultUpstream, with WatchEgress, ends a stdio run by failing every
	// connection the server makes and calling a few tools that already
	// succeeded, to see whether a call whose dependency is down comes back
	// with an error or hangs. Off by default: it is the one part of a run
	// that deliberately makes the server's world worse.
	FaultUpstream bool
	// PlantCanaries points the child's HOME at a scratch directory seeded
	// with decoy credentials, so a server that goes looking for one can
	// be seen doing it.
	//
	// Off by default and stdio only: it works by deciding where HOME
	// points, which is only possible for a process passmcp started.
	PlantCanaries bool
	// Baseline is the approved catalogue to compare against, or nil to
	// make no comparison.
	//
	// The snapshot itself rather than a path, for the reason RunSpec.Gate
	// carries its policy by value: a spec that crosses a network must
	// never ask the receiving process to open a file somebody else named.
	Baseline *baseline.Snapshot
	// ClientConfig is the MCP client configuration the operator supplied:
	// which servers an agent uses together, and how each stdio server is
	// started. Nil makes no cross-server comparison and reads no launch
	// command. Carried by value, like Baseline.
	ClientConfig *clientconf.Config

	// Only and Skip select phases by name.
	Only []string
	Skip []string

	// Progress is called as phases start and findings land.
	Progress func(phase string, f *Finding)
	// PhaseDone is called with each phase's result, including skipped ones.
	PhaseDone func(PhaseResult)
}

// TokenInfo is what the auth phase learned about the token in use.
type TokenInfo struct {
	Type        string    `json:"type,omitempty"`
	Scope       string    `json:"scope,omitempty"`
	Requested   string    `json:"requested_scope,omitempty"`
	Expiry      time.Time `json:"expiry,omitempty"`
	Refreshable bool      `json:"refreshable"`
	Source      string    `json:"source,omitempty"`
}

// Session is the shared state across phases.
type Session struct {
	Opts      Options
	Started   time.Time
	TraceID   string
	URL       *url.URL
	Client    *passmcp.Client
	Transport http.RoundTripper // recorder-wrapped base
	// Bare is a transport to the endpoint with tracing and recording but
	// no credentials of any kind, for probes that must arrive
	// unauthenticated. Nil over stdio: there is no unauthenticated view of
	// a program the operator chose to run.
	Bare *transport.Streamable
	// Snapshot is the catalogue this run saw, set when a baseline was
	// supplied. It is what --approve promotes.
	Snapshot *baseline.Snapshot

	// Proxy is the egress witness, when one is running.
	Proxy *egress.Proxy
	// Canary is the planted scratch home, when one was seeded.
	Canary *canary.Canary
	// witness samples the child's process group from the end of the
	// handshake; witnessErr is why there is none, and witnessed is what it
	// saw once stopped.
	witness    *witness.Watcher
	witnessErr error
	witnessed  *witness.Observed
	// Build is what the target binary is made of, when it is a Go program
	// passmcp could read.
	Build *supply.Build
	// canaryHits is every decoy whose marker was seen in something the
	// server said, and where. Written from the reader goroutine.
	canaryMu   sync.Mutex
	canaryHits map[string]string
	// canaryErr is why there is none, when one was asked for.
	canaryErr string
	// egressErr is why there is no witness, when one was asked for.
	egressErr string

	// Pipe is the child-process transport, or nil over HTTP. It is the one
	// place a phase asks which kind of run this is.
	Pipe *transport.Stdio

	// Reached is set once the endpoint answered an HTTP request at all.
	Reached      bool
	RequiresAuth bool
	Challenge    auth.Challenge
	Discovery    *passmcp.Discovery
	// Era is which generation of the protocol the server speaks.
	Era       *passmcp.Negotiation
	Token     *TokenInfo
	Init      *passmcp.InitializeResult
	SessionID bool

	Tools     []passmcp.Tool
	Resources []passmcp.Resource
	Templates []passmcp.ResourceTemplate
	Prompts   []passmcp.Prompt
	// PersonalData lists the tools whose schemas name personal-data
	// fields, as catalog.personal_data found them. It feeds the Art.
	// 30-style record `passmcp evidence --framework gdpr` writes.
	PersonalData []PersonalDataTool

	ToolResults     []ToolResult
	ResourceResults []ResourceResult
	PromptResults   []PromptResult
	Perf            *PerfResult
	// outputRefs are the requests whose results the output scan read, and
	// outputHits the ones that addressed the model.
	outputRefs []string
	outputHits []outputHit
	// toolsListRef cites the tools/list requests the catalogue was read
	// from, for the checks that judge what that listing said rather than
	// making a request of their own (ADR 0002).
	toolsListRef string
	// MRTR records every input_required result the run saw, so
	// protocol.mrtr can judge whether they were answerable. Observational
	// rather than probed: passmcp cannot make a server ask for input, and a
	// tool that needs it is the only thing that produces one.
	MRTR []MRTRObservation

	Results []PhaseResult
	blocked string
}

// Phase is one diagnostic step.
type Phase struct {
	Name  string
	Title string
	// Describe says in one line what the phase checks.
	Describe string
	Run      func(ctx context.Context, s *Session) []Finding
	// RunStdio replaces Run when the server is a child process, for a
	// phase whose question still has an answer over a pipe but a different
	// subject. Nil means Run handles both.
	RunStdio func(ctx context.Context, s *Session) []Finding
	// StdioSkip is why this phase has no subject over a pipe. Set, the
	// phase is reported as skipped with this reason rather than omitted:
	// the difference between a report that is honest about what it did not
	// look at and one that reads as a clean result.
	StdioSkip string
}

// Phases in execution order.
var Phases = []Phase{
	{Name: "net", Title: "Connectivity", Describe: "DNS, TCP and TLS", Run: phaseNet, RunStdio: phaseNetStdio},
	{Name: "discovery", Title: "Authorization", Describe: "How the server asks to be authorized", Run: phaseDiscovery,
		StdioSkip: "a child process has no origin and no metadata to discover. " +
			"The trust decision was made when the operator chose which program to run, and passmcp cannot second-guess it from here"},
	{Name: "auth", Title: "Credentials", Describe: "Your credentials, and whether bad ones are refused", Run: phaseAuth,
		StdioSkip: "there is nothing to authenticate to. A pipe carries no bearer token, so there is also no wrong one to send " +
			"and no refusal to check; a server that needs a secret is given it in its arguments or its environment"},
	{Name: "handshake", Title: "Handshake", Describe: "The MCP initialize exchange", Run: phaseHandshake},
	{Name: "protocol", Title: "Protocol", Describe: "Behaviour on edge cases an agent will hit", Run: phaseProtocol},
	{Name: "catalog", Title: "Catalog", Describe: "Tools, resources and prompts, as an agent reads them", Run: phaseCatalog},
	{Name: "execution", Title: "Execution", Describe: "Safe calls, results checked against their contracts", Run: phaseExecution},
	{Name: "performance", Title: "Performance", Describe: "Latency under repeat and parallel calls", Run: phasePerformance},
	{Name: "resilience", Title: "Resilience", Describe: "Recovery from a lost session or an expired token", Run: phaseResilience,
		RunStdio: phaseResilienceStdio},
}

// PhaseTitle returns the human title of a phase, or the name itself when
// it is not one passmcp knows.
func PhaseTitle(name string) string {
	for _, p := range Phases {
		if p.Name == name {
			return p.Title
		}
	}
	return name
}

// PhaseNames lists the phase names in order.
func PhaseNames() []string {
	out := make([]string, len(Phases))
	for i, p := range Phases {
		out[i] = p.Name
	}
	return out
}

// Run executes the selected phases.
func Run(ctx context.Context, opts Options) (*Session, error) {
	opts = withDefaults(opts)
	ctx = trace.Ensure(ctx)

	if opts.Stdio != nil {
		if opts.Endpoint != "" {
			return nil, errors.New("a run has one target: an endpoint or a command, not both")
		}
		return runStdio(ctx, opts)
	}

	u, err := url.Parse(opts.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("endpoint %q is not an absolute URL", opts.Endpoint)
	}
	s := &Session{Opts: opts, Started: time.Now(), TraceID: trace.FromContext(ctx), URL: u}
	if err := s.connectHTTP(ctx); err != nil {
		return nil, err
	}
	return s.runPhases(ctx)
}

// withDefaults fills in what the caller left zero, and registers every
// credential secret with the recorder's redactor. That happens here, before
// any client exists, so no request can be recorded ahead of the secret it
// might carry.
func withDefaults(opts Options) Options {
	if opts.Recorder == nil {
		opts.Recorder = telemetry.New()
	}
	if opts.Creds == nil {
		opts.Creds = &creds.Credentials{Mode: creds.ModeNone}
	}
	for _, sec := range opts.Creds.Secrets() {
		opts.Recorder.Redactor.Add(sec)
	}
	// A client configuration's env and header values reach the servers it
	// names, and so the telemetry of this run when those are listed.
	for _, sec := range opts.ClientConfig.Secrets() {
		opts.Recorder.Redactor.Add(sec)
	}
	if opts.CallTimeout == 0 {
		opts.CallTimeout = 30 * time.Second
	}
	if opts.Samples == 0 {
		opts.Samples = 5
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 4
	}
	if opts.MaxResources == 0 {
		opts.MaxResources = 25
	}
	if opts.MaxPrompts == 0 {
		opts.MaxPrompts = 25
	}
	return opts
}

// connectHTTP builds the session's two transports to an HTTP endpoint: the
// client carrying the operator's credentials, and the bare transport that
// carries nothing but the trace header.
func (s *Session) connectHTTP(ctx context.Context) error {
	opts, u := s.Opts, s.URL

	base := opts.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 60 * time.Second}
	}
	pol := opts.URLPolicy
	if !pol.AllowPrivate && endpointIsPrivate(ctx, u) {
		// The operator pointed passmcp at a host inside their own network, so
		// an authorization server in the same place is expected rather than
		// suspicious. The guard still applies to a public endpoint naming an
		// internal one, which is the case that matters.
		pol.AllowPrivate = true
	}
	hc := *base
	rt := base.Transport
	if rt == nil {
		// The policy again at connect time, for every host but the
		// operator's own: a discovered name must not resolve one way for
		// the check and another for the connection (DNS rebinding).
		rt = pol.Transport(opts.Dial, u.Hostname())
	}
	hc.Transport = opts.Recorder.Wrap(rt)
	if opts.UserAgent != "" {
		// Outside the recorder, so the header it sets is the one recorded,
		// and underneath both transports, so the bare one carries it too.
		hc.Transport = userAgentTransport{base: hc.Transport, ua: opts.UserAgent}
	}
	s.Transport = hc.Transport

	cfg := passmcp.Config{
		Endpoint: opts.Endpoint, HTTPClient: &hc,
		ClientInfo:            passmcp.Implementation{Name: "passmcp", Version: opts.Version},
		URLPolicy:             pol,
		AllowResourceMismatch: opts.AllowResourceMismatch,
	}
	opts.Creds.Apply(&cfg)
	client, err := passmcp.New(cfg)
	if err != nil {
		return err
	}
	s.Client = client
	bare := hc
	bare.Transport = trace.RoundTripper{Base: hc.Transport}
	s.Bare = transport.New(opts.Endpoint, &bare)
	return nil
}

// runStdio starts the server as a child process and runs the same phases
// against it.
//
// The process is this function's for its whole life: it is started here and
// reaped here, on every path out including a panic in a phase. A diagnostic
// that leaves a server running has done damage no report undoes, and the
// place to guarantee that is the one place that started it.
func runStdio(ctx context.Context, opts Options) (s *Session, err error) {
	s = &Session{Opts: opts, Started: time.Now(), TraceID: trace.FromContext(ctx)}

	cfg := *opts.Stdio
	cfg.Observe = s.recordPipe(s.command())

	// Before the process, because the address has to be in the
	// environment the process is started with. A proxy that failed to
	// listen is not a reason to abandon the run: every other check still
	// has something to say, and the egress checks report that they could
	// not watch.
	if opts.WatchEgress {
		if px, err := egress.Start(nil); err != nil {
			s.egressErr = err.Error()
		} else {
			s.Proxy = px
			cfg.Inject = append(append([]string{}, cfg.Inject...), px.Env()...)
			defer func() { _ = px.Close() }()
		}
	}

	// The decoys, for the same reason and at the same moment: HOME has to
	// be set before the process reads it.
	if opts.PlantCanaries {
		if cn := s.plantCanaries(&cfg); cn != nil {
			// Removed after the findings are built, not here: Opened()
			// reads the access times off these files.
			defer func() { _ = cn.Close() }()
		}
	}
	client, cerr := passmcp.NewStdio(ctx, passmcp.Config{
		Stdio:      &cfg,
		ClientInfo: passmcp.Implementation{Name: "passmcp", Version: opts.Version},
	})
	if cerr != nil {
		return nil, cerr
	}
	s.Client = client
	pipe, ok := client.Stdio()
	if !ok {
		// Unreachable unless the client stops honouring Config.Stdio, and a
		// nil Pipe would panic in the first phase instead of saying so.
		_ = client.Close()
		return nil, errors.New("internal: a stdio client without a pipe")
	}
	s.Pipe = pipe
	var once sync.Once
	shutdown := func() { once.Do(func() { _ = client.Close() }) }
	defer shutdown()

	// Which generation the server speaks is settled before the handshake,
	// as it is over HTTP — but on the pipe rather than on a credential-free
	// transport, because there is no such thing here.
	s.settleEraStdio(ctx)

	res, rerr := s.runPhases(ctx)
	// Whichever phases ran, the sampler stops with the run. stopWitness is
	// idempotent, so the resilience phase having stopped it already is fine.
	s.stopWitness()
	if rerr != nil {
		return res, rerr
	}
	// Two checks can only be made once the process is gone: whether it
	// stopped when its input closed, and whether anything it started
	// outlived it. So the shutdown happens here rather than on the defer,
	// and the resilience phase adopts what it found.
	shutdown()
	s.adoptCustody()
	return res, nil
}

// plantCanaries seeds the decoys, puts them in the server's environment and
// watches the pipe and the egress proxy for their markers. It returns nil,
// recording why, when the decoys could not be seeded; the caller owns
// closing the ones it gets.
func (s *Session) plantCanaries(cfg *passmcp.StdioConfig) *canary.Canary {
	cn, err := canary.Seed("")
	if err != nil {
		s.canaryErr = err.Error()
		return nil
	}
	s.Canary = cn
	cfg.Inject = append(append([]string{}, cfg.Inject...), cn.Env()...)
	if s.Proxy != nil {
		// So a marker leaving in a plain request body is seen at
		// the moment it leaves, rather than inferred afterwards.
		s.Proxy.WatchFor(cn.Markers())
	}
	// Scanned as it arrives rather than read back off the
	// recorder, which keeps bodies only under --capture-bodies.
	inner := cfg.Observe
	cfg.Observe = func(ctx context.Context, m transport.StdioMessage) {
		s.noteCanaries(m.Received, "sent back to passmcp over the pipe")
		if inner != nil {
			inner(ctx, m)
		}
	}
	return cn
}

// runPhases executes the selected phases against a prepared session. It is
// shared so that adding a transport cannot accidentally give one of them a
// different loop, a different skip rule or a different order.
func (s *Session) runPhases(ctx context.Context) (*Session, error) {
	opts := s.Opts
	for _, p := range Phases {
		if !selected(p.Name, opts) {
			continue
		}
		pr := s.runPhase(ctx, p)
		s.Results = append(s.Results, pr)
		if p.Name == "handshake" && s.overStdio() && s.blocked == "" {
			// Everything open until now is bootstrap. From here on, the only
			// reason the server acts is a request passmcp sent.
			s.startWitness()
		}
		if opts.PhaseDone != nil {
			opts.PhaseDone(pr)
		}
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
	}
	return s, nil
}

// runPhase runs one selected phase, or records why it was skipped, and
// returns its result with the duration filled in.
func (s *Session) runPhase(ctx context.Context, p Phase) PhaseResult {
	opts := s.Opts
	start := time.Now()
	pr := PhaseResult{Name: p.Name, Title: p.Title, Started: start}
	run := p.Run
	if s.overStdio() && p.RunStdio != nil {
		run = p.RunStdio
	}
	switch {
	// A blocked run skips the phases that would only produce
	// meaningless failures against a server that is not answering. The
	// exception over stdio is every phase with its own stdio
	// implementation: those look at the process passmcp started rather
	// than at the protocol, so they always have an answer — and a run
	// that got blocked is exactly when "the server wrote a banner to
	// stdout" or "the process exited" is the finding that explains
	// everything else.
	case s.blocked != "" && p.Name != "net" && !s.observesTheProcess(p):
		pr.Status, pr.Skipped = Skip, s.blocked
	case s.overStdio() && p.StdioSkip != "":
		pr.Status, pr.Skipped = Skip, p.StdioSkip
	default:
		if opts.Progress != nil {
			opts.Progress(p.Name, nil)
		}
		pctx := telemetry.WithPhase(ctx, p.Name, "")
		pr.Findings = run(pctx, s)
		pr.Status = worst(pr.Findings)
		pr.Summary = summarize(p.Name, s, pr)
		for i := range pr.Findings {
			pr.Findings[i].Phase = p.Name
			if opts.Progress != nil {
				opts.Progress(p.Name, &pr.Findings[i])
			}
		}
	}
	pr.Duration = Millis(time.Since(start))
	return pr
}

// endpointIsPrivate reports whether the endpoint the operator named is
// itself on a non-public address.
func endpointIsPrivate(ctx context.Context, u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.IP.IsLoopback() || a.IP.IsPrivate() || a.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func selected(name string, o Options) bool {
	if len(o.Only) > 0 && !slices.Contains(o.Only, name) {
		return false
	}
	return !slices.Contains(o.Skip, name)
}

func worst(fs []Finding) Status {
	if len(fs) == 0 {
		return Skip
	}
	rank := map[Status]int{Skip: 0, Info: 1, Pass: 2, Warn: 3, Fail: 4}
	w := Skip
	allSkip := true
	for _, f := range fs {
		if f.Status != Skip {
			allSkip = false
		}
		if rank[f.Status] > rank[w] {
			w = f.Status
		}
	}
	if allSkip {
		return Skip
	}
	if w == Info {
		return Pass
	}
	return w
}

// --- finding builder ------------------------------------------------------

type check struct {
	s     *Session
	f     Finding
	from  int
	start time.Time
}

func (s *Session) check(id, title string) *check {
	return &check{s: s, f: Finding{ID: id, Title: title}, from: s.Opts.Recorder.Count(), start: time.Now()}
}

func (c *check) done(st Status, sev Severity, detail, advice string) Finding {
	c.f.Status, c.f.Severity, c.f.Detail, c.f.Advice = st, sev, oneLine(detail), advice
	c.f.DocURL = DocURL(c.f.ID)
	c.f.Controls = controls.For(c.f.ID)
	c.f.Duration = Millis(time.Since(c.start))
	if to := c.s.Opts.Recorder.Count(); to > c.from {
		if to-c.from == 1 {
			c.f.Evidence = append(c.f.Evidence, fmt.Sprintf("req#%d", to))
		} else {
			c.f.Evidence = append(c.f.Evidence, fmt.Sprintf("req#%d-%d", c.from+1, to))
		}
	}
	return enforceEvidence(c.f)
}

func (c *check) pass(detail string) Finding                  { return c.done(Pass, "", detail, "") }
func (c *check) info(detail string) Finding                  { return c.done(Info, "", detail, "") }
func (c *check) skip(reason string) Finding                  { return c.done(Skip, "", reason, "") }
func (c *check) warn(detail, advice string) Finding          { return c.done(Warn, Minor, detail, advice) }
func (c *check) fail(sev Severity, d, advice string) Finding { return c.done(Fail, sev, d, advice) }
func (c *check) ev(items ...string) *check                   { c.f.Evidence = append(c.f.Evidence, items...); return c }

// oneLine collapses whitespace in a detail.
//
// A detail is one line in every rendering passmcp produces, and some of what
// goes into one comes from the server: a validation library that returns a
// pretty-printed array puts its newlines straight through the terminal
// layout, the Markdown table and the JUnit message. Nothing writes a detail
// that means to be multi-line, so this is a normalisation rather than a
// truncation — the text is all still there.
func oneLine(s string) string {
	if !strings.ContainsAny(s, "\n\r\t") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ms renders a duration in milliseconds. It accepts both time.Duration and
// Millis so call sites need not convert.
func ms[T ~int64](d T) string { return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond)) }

// Blocked returns the reason later phases were skipped, or "".
func (s *Session) Blocked() string { return s.blocked }

// userAgentTransport sets one User-Agent on every request it carries. The
// request is cloned first: a RoundTripper must not modify the caller's.
type userAgentTransport struct {
	base http.RoundTripper
	ua   string
}

// RoundTrip sends r with the configured User-Agent.
func (t userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", t.ua)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
