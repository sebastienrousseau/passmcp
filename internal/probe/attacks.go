// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/clientconf"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// The attack classes that 2025–2026 research found most exploited are the
// ones a single-server, single-request view covers least: shadowing across
// servers configured together, a server holding both halves of an
// exfiltration, instructions arriving in tool output rather than in the
// catalogue, a token accepted for the wrong resource, a local server
// listening on every interface, and a launch command that runs whatever a
// URL serves. Every check here stays inside the same rules as the rest of
// passmcp: it reads, it cites the request that showed it, it never forges a
// credential and it never calls a tool the policy did not allow (ADR 0002,
// ADR 0004, ADR 0008).

// --- ATK-02: capabilities that combine into an exfiltration path ---------------

// splitName breaks a tool name into lower-case words at separators and
// camel-case boundaries: read_file, readFile and read-file all give
// [read file].
func splitName(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && len(cur) > 0 && unicode.IsLower(cur[len(cur)-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// privateNouns are what a tool reads when what it reads is the user's or the
// host's rather than the public web's.
var privateNouns = map[string]bool{
	"file": true, "files": true, "dir": true, "directory": true, "folder": true, "path": true,
	"document": true, "documents": true, "db": true, "database": true, "sql": true, "table": true,
	"record": true, "records": true, "email": true, "emails": true, "inbox": true, "mail": true,
	"messages": true, "contact": true, "contacts": true, "calendar": true, "note": true, "notes": true,
	"secret": true, "secrets": true, "credential": true, "credentials": true, "env": true,
	"clipboard": true, "history": true, "customer": true, "customers": true, "account": true,
	"accounts": true, "repo": true, "repository": true, "issue": true, "issues": true,
}

var readVerbs = map[string]bool{
	"read": true, "get": true, "list": true, "search": true, "query": true, "load": true,
	"open": true, "view": true, "cat": true, "find": true, "lookup": true, "fetch": true, "show": true,
}

// sendVerbs are what a tool does when it moves data somewhere the user does
// not control.
var sendVerbs = map[string]bool{
	"send": true, "post": true, "publish": true, "upload": true, "notify": true, "share": true,
	"forward": true, "tweet": true, "webhook": true, "curl": true, "email": true, "mail": true,
}

var outboundNouns = map[string]bool{"url": true, "webhook": true, "http": true, "https": true}

var privateDescRe = regexp.MustCompile(`(?i)\b(reads?|returns?|lists?|retrieves?|searches|gets?|loads?)\b.{0,40}\b(local (files?|disk)|file ?system|files? on (disk|the machine)|private|personal data|confidential|credentials?|secrets?|database|inbox|e-?mails?|clipboard|home directory)\b`)

var outboundDescRe = regexp.MustCompile(`(?i)\b(sends?|posts?|publishes|uploads?|forwards?)\b.{0,40}\b(e-?mail|message|webhook|url|endpoint|server|channel|external|anyone|recipient)s?\b|\b(http requests? to (any|an arbitrary|the given)|arbitrary urls?|outbound requests?)\b`)

// privateReader returns why t reads local or private data, or nil when
// nothing says it does. The name or the description must say so; an
// annotation or a schema field only supports a reading, never makes one.
func privateReader(t passmcp.Tool) []string {
	var why []string
	words := splitName(t.Name)
	verb, noun := false, ""
	for _, w := range words {
		verb = verb || readVerbs[w]
		if privateNouns[w] && noun == "" {
			noun = w
		}
	}
	if verb && noun != "" {
		why = append(why, fmt.Sprintf("name %q reads %s", t.Name, noun))
	}
	if m := privateDescRe.FindString(t.Description); m != "" {
		why = append(why, fmt.Sprintf("description says it %q", truncate(m, 60)))
	}
	if len(why) == 0 {
		return nil
	}
	if f := schemaField(t.InputSchema, "path", "file", "filepath", "filename", "directory", "dir", "sql"); f != "" {
		why = append(why, "inputSchema takes "+f)
	}
	if a := t.Annotations; a != nil && a.OpenWorldHint != nil && !*a.OpenWorldHint {
		why = append(why, "openWorldHint: false")
	}
	return why
}

// outboundSender returns why t sends data outside the user's control, or
// nil when nothing says it does. An explicit openWorldHint on a tool that
// is not read-only is a statement the server made about itself, so it is
// enough on its own.
func outboundSender(t passmcp.Tool) []string {
	var why []string
	words := splitName(t.Name)
	for i, w := range words {
		if sendVerbs[w] || (outboundNouns[w] && i > 0) {
			why = append(why, fmt.Sprintf("name %q sends data out", t.Name))
			break
		}
	}
	if m := outboundDescRe.FindString(t.Description); m != "" {
		why = append(why, fmt.Sprintf("description says it %q", truncate(m, 60)))
	}
	if a := t.Annotations; a != nil && a.OpenWorldHint != nil && *a.OpenWorldHint &&
		(a.ReadOnlyHint == nil || !*a.ReadOnlyHint) {
		why = append(why, "openWorldHint: true and not read-only")
	}
	return why
}

// schemaField returns the first property of an object schema whose name is
// one of names, or "".
func schemaField(raw json.RawMessage, names ...string) string {
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	props := make([]string, 0, len(doc.Properties))
	for p := range doc.Properties {
		props = append(props, p)
	}
	sort.Strings(props)
	for _, p := range props {
		for _, n := range names {
			if strings.EqualFold(p, n) {
				return p
			}
		}
	}
	return ""
}

// capability is one tool and why it was read as holding a capability.
type capability struct {
	tool string
	why  []string
}

// checkToxicCombination reports a server that exposes both halves of an
// exfiltration: a tool that reads what is private, and another that sends
// data out. Neither is a defect alone, and together they are exactly what a
// prompt injection needs, whoever authored the catalogue.
func checkToxicCombination(s *Session) Finding {
	c := s.check("catalog.toxic_combination", "No tool pair reads private data and sends it out")
	var readers, senders []capability
	for _, t := range s.Tools {
		if why := privateReader(t); why != nil {
			readers = append(readers, capability{t.Name, why})
		}
		if why := outboundSender(t); why != nil {
			senders = append(senders, capability{t.Name, why})
		}
	}
	var pairs []string
	for _, r := range readers {
		for _, w := range senders {
			if r.tool == w.tool {
				continue
			}
			pairs = append(pairs, fmt.Sprintf("%s (reads: %s) with %s (sends: %s)",
				r.tool, strings.Join(r.why, "; "), w.tool, strings.Join(w.why, "; ")))
		}
	}
	if len(pairs) == 0 {
		return c.pass(fmt.Sprintf("%d tools: none reads local or private data beside another that sends data out", len(s.Tools)))
	}
	shown := min(len(pairs), 3)
	detail := fmt.Sprintf("%d pair(s): %s", len(pairs), strings.Join(pairs[:shown], "; "))
	if len(pairs) > shown {
		detail += fmt.Sprintf("; and %d more", len(pairs)-shown)
	}
	return c.warn(s.Opts.Recorder.Redactor.String(detail),
		"split the reading and the sending across servers an operator approves separately, or require confirmation for the sending tool: an agent that can do both can be told by any text it reads to send what it read")
}

// --- ATK-03: instructions arriving in tool output --------------------------------

// outputHit is one tool result that carried text addressed to the model.
type outputHit struct {
	tool, ref, detail, excerpt string
}

// reqRef names the requests the recorder saw between two counts.
func reqRef(from, to int) string {
	switch {
	case to <= from:
		return ""
	case to-from == 1:
		return fmt.Sprintf("req#%d", to)
	default:
		return fmt.Sprintf("req#%d-%d", from+1, to)
	}
}

// noteOutput scans one successful result for instructions addressed to the
// model. Only the critical and major instruction rules apply: a phrase like
// "always include" is ordinary in data and would drown the finding that
// matters.
func (s *Session) noteOutput(tool string, res *passmcp.CallToolResult, ref string) {
	if res == nil || ref == "" {
		return
	}
	text := res.Text()
	if len(res.StructuredContent) > 0 {
		text += "\n" + string(res.StructuredContent)
	}
	s.outputRefs = append(s.outputRefs, ref)
	for _, sig := range diagnostics.ScanText("tool "+tool+" output", text) {
		if sig.Kind != diagnostics.SignalInstruction || sig.Severity == diagnostics.SeverityMinor {
			continue
		}
		s.outputHits = append(s.outputHits, outputHit{
			tool: tool, ref: ref, detail: sig.Detail,
			excerpt: s.Opts.Recorder.Redactor.String(truncate(sig.Excerpt, 120)),
		})
		return // one per result: the call is the unit an operator acts on
	}
}

// checkOutputInjection reports tool results that address the model.
func checkOutputInjection(s *Session) Finding {
	c := s.check("execution.output_injection", "Tool results describe rather than instruct")
	if len(s.outputRefs) == 0 {
		return c.skip("no call returned a result to read")
	}
	if len(s.outputHits) == 0 {
		return c.ev(s.outputRefs...).pass(fmt.Sprintf("%s read; none addresses the model", plural(len(s.outputRefs), "result")))
	}
	var parts []string
	for _, h := range s.outputHits {
		c.ev(h.ref)
		parts = append(parts, fmt.Sprintf("%s (%s) %s — %q", h.tool, h.ref, h.detail, h.excerpt))
	}
	return c.warn(fmt.Sprintf("%s addressed to the model: %s", plural(len(s.outputHits), "result"), strings.Join(parts, "; ")),
		"return data, not directions: text in a result reaches the model with the authority of the conversation, and whoever can write into what the tool reads can steer the agent through it")
}

// --- ATK-04: a token minted for another resource ----------------------------------

// checkWrongAudience sends the token the operator obtained from their own
// authorization server for a different resource. passmcp never mints or
// alters a token: without one supplied, the check says so and does not run.
// Like auth.rejects_garbage it goes on the bare transport, so the real token
// the client carries cannot ride along (ADR 0001).
func checkWrongAudience(ctx context.Context, s *Session) Finding {
	c := s.check("auth.wrong_audience", "Server rejects a token minted for another resource")
	tok := s.Opts.Creds.WrongAudienceToken
	if tok == "" {
		return c.skip("no token for another resource was supplied: obtain one from your authorization server for a different resource and pass it with --wrong-audience-token-env NAME; passmcp never forges one")
	}
	tr := s.Bare
	id := tr.NextID()
	raw, err := tr.Do(telemetry.WithPhase(ctx, "auth", "wrong-audience token"), transport.RawOptions{
		Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: initParams(s)},
		Headers: map[string]string{"Authorization": "Bearer " + tok}, OmitSession: true,
	})
	tr.Reset()
	switch {
	case err != nil:
		return c.warn("request failed: "+s.Opts.Recorder.Redactor.String(err.Error()), "")
	case raw.Status == http.StatusUnauthorized:
		return c.pass("401: the token issued for another resource was refused")
	case raw.Status == http.StatusForbidden:
		return c.warn("403 for a token issued for another resource; 401 with invalid_token is expected", "return 401 for a token whose audience is not this server")
	case raw.Status/100 == 2:
		return c.fail(Critical, fmt.Sprintf("HTTP %d: the server accepted a token issued for a different resource", raw.Status),
			"validate the token's audience (RFC 8707, the MCP authorization specification): a server that accepts another resource's token lets any service the user authorized act as the user here, and passes tokens through where it should refuse them")
	default:
		return c.warn(fmt.Sprintf("HTTP %d for a token issued for another resource", raw.Status), "return 401")
	}
}

// --- ATK-05: a local server listening on every interface ----------------------------

// checkBindAll reports a stdio server that opened a listening socket on
// 0.0.0.0 or ::. A program started to speak over its pipes has no reason to
// accept connections from the network, and one that does is reachable by
// anyone on it — the NeighborJack study found hundreds.
func checkBindAll(s *Session, skipReason string) Finding {
	c := s.check("stdio.bind_all", "Server listens on no public interface")
	if s.witnessed == nil {
		return c.skip(skipReason)
	}
	o := *s.witnessed
	limit := fmt.Sprintf("sampled every %s, %d time(s), from the handshake; a socket opened and closed between two samples is not seen", o.Interval, o.Samples)
	var open []string
	for _, l := range o.Listening {
		if l.AllInterfaces() {
			open = append(open, fmt.Sprintf("%s %s (port %s)", l.Proto, l.Local, l.Port()))
		}
	}
	if len(open) > 0 {
		return c.ev(open...).fail(Major,
			fmt.Sprintf("listening on every interface: %s (%s)", strings.Join(open, ", "), limit),
			"bind to 127.0.0.1 or ::1, or do not listen at all: a stdio server speaks over its pipes, and a port on every interface is reachable from the whole network")
	}
	return c.info(fmt.Sprintf("%s held; none bound to every interface (%s)", plural(len(o.Listening), "listening socket"), limit))
}

// --- ATK-06: the launch command in a client configuration ---------------------------

// launchConfigFindings reads every stdio server's launch command in the
// client configuration the operator supplied. Nothing is started; the file
// is the evidence, cited by line.
func launchConfigFindings(s *Session) []Finding {
	cfg := s.Opts.ClientConfig
	if cfg == nil {
		return nil
	}
	c := s.check("stdio.launch_config", "Launch commands carry no shell, download or secret")
	stdio := 0
	for _, srv := range cfg.Servers {
		if srv.Stdio() {
			stdio++
		}
	}
	if stdio == 0 {
		return []Finding{c.info(fmt.Sprintf("%s names no stdio server, so there is no launch command to read", cfg.Path))}
	}
	issues := cfg.Audit()
	if len(issues) == 0 {
		return []Finding{c.info(fmt.Sprintf("%s read in %s: no shell, no download-and-run, no unpinned package, no secret in the arguments",
			plural(stdio, "launch command"), cfg.Path))}
	}
	var parts []string
	for _, is := range issues {
		c.ev(fmt.Sprintf("%s:%d", cfg.Path, is.Line))
		parts = append(parts, fmt.Sprintf("%s (line %d, %s): %s", is.Server, is.Line, is.Kind, is.Detail))
	}
	shown := min(len(parts), 5)
	detail := fmt.Sprintf("%s in %s: %s", plural(len(issues), "issue"), cfg.Path, strings.Join(parts[:shown], "; "))
	if len(parts) > shown {
		detail += fmt.Sprintf("; and %d more", len(parts)-shown)
	}
	return []Finding{c.warn(s.Opts.Recorder.Redactor.String(detail),
		"start the server directly, not through a shell; pin every package to a version; pass credentials in env, never as arguments; and never launch what a URL serves at the moment of launch")}
}

// --- ATK-01: shadowing across the servers a client configures together -----------

// checkCrossServerShadowing compares this server's catalogue text with the
// tool names of the other servers in the client configuration. The other
// catalogues are listed read-only: initialize and tools/list, nothing
// called, and no credential of this run sent to any of them.
func checkCrossServerShadowing(ctx context.Context, s *Session) (Finding, bool) {
	cfg := s.Opts.ClientConfig
	if cfg == nil {
		return Finding{}, false
	}
	c := s.check("catalog.text.cross_server_shadowing", "No description governs another configured server's tool")
	if len(cfg.Servers) < 2 {
		return c.skip(fmt.Sprintf("%s names %s; shadowing across servers needs two or more", cfg.Path, plural(len(cfg.Servers), "server"))), true
	}
	if len(s.Tools) == 0 {
		return c.skip("this server listed no tools, so it has no description to compare"), true
	}
	self, peers := splitPeers(cfg, s)
	servers, failed := listPeers(ctx, s, peers)
	servers = append([]OverlapServer{{Name: self, Tools: s.Tools}}, servers...)
	if len(servers) < 2 {
		return c.skip("no other configured server's tools could be listed: " + strings.Join(failed, "; ")), true
	}
	var found []string
	for _, o := range FindOverlaps(servers) {
		if o.Kind != "shadowing" || o.Servers[0] != self {
			continue
		}
		found = append(found, fmt.Sprintf("%s's %s steers the agent toward %s, which %s exposes — %q",
			self, strings.TrimPrefix(o.Where, "tool "), o.Tool, strings.Join(o.Servers[1:], ", "), o.Quote))
	}
	note := ""
	if len(failed) > 0 {
		note = "; not compared: " + strings.Join(failed, "; ")
	}
	if len(found) > 0 {
		return c.fail(Major, fmt.Sprintf("%s%s", strings.Join(found, "; "), note),
			"describe only this server's own tools: text that attaches a rule to another server's tool is how one server in an agent's configuration takes over what the others do"), true
	}
	return c.pass(fmt.Sprintf("compared with %s: no description here governs another server's tool%s",
		plural(len(servers)-1, "other server"), note)), true
}

// listPeers lists every peer's tools, and says why for each it could not.
// A stdio peer whose launch command the audit flagged is not started:
// passmcp does not run a shell, a download or an unpinned package to read a
// catalogue, and stdio.launch_config already reports why.
func listPeers(ctx context.Context, s *Session, peers []clientconf.Server) ([]OverlapServer, []string) {
	flagged := map[string]bool{}
	for _, is := range s.Opts.ClientConfig.Audit() {
		flagged[is.Server] = true
	}
	var servers []OverlapServer
	var failed []string
	for _, p := range peers {
		if p.Stdio() && flagged[p.Name] {
			failed = append(failed, p.Name+": not started, its launch command is flagged by stdio.launch_config")
			continue
		}
		tools, err := peerTools(ctx, s, p)
		if err != nil {
			failed = append(failed, p.Name+": "+truncate(s.Opts.Recorder.Redactor.String(err.Error()), 120))
			continue
		}
		servers = append(servers, OverlapServer{Name: p.Name, Tools: tools})
	}
	return servers, failed
}

// splitPeers names this server as the configuration names it, when it is in
// the configuration, and returns every other configured server.
func splitPeers(cfg *clientconf.Config, s *Session) (string, []clientconf.Server) {
	self := s.Opts.Endpoint
	if s.Opts.Stdio != nil {
		self = s.command()
	}
	name := self
	var peers []clientconf.Server
	for _, srv := range cfg.Servers {
		if sameTarget(srv, s) {
			name = srv.Name
			continue
		}
		peers = append(peers, srv)
	}
	return name, peers
}

// sameTarget reports whether a configured server is the one under test.
func sameTarget(srv clientconf.Server, s *Session) bool {
	if s.Opts.Stdio != nil {
		return srv.Stdio() && srv.Describe() == strings.TrimSpace(s.command())
	}
	return !srv.Stdio() && strings.TrimRight(srv.URL, "/") == strings.TrimRight(s.Opts.Endpoint, "/")
}

// peerTools lists one configured server's tools: initialize, then
// tools/list, recorded like every other request so the finding can cite
// them. A remote peer gets only the headers its own entry configures; a
// stdio peer is started as the host would start it, with the host's base
// environment plus its configured env, and stopped straight after.
func peerTools(ctx context.Context, s *Session, p clientconf.Server) ([]passmcp.Tool, error) {
	cctx, cancel := context.WithTimeout(telemetry.WithPhase(ctx, "catalog", "peer "+p.Name), s.Opts.CallTimeout)
	defer cancel()
	cfg := passmcp.Config{ClientInfo: passmcp.Implementation{Name: "passmcp", Version: s.Opts.Version}}
	var client *passmcp.Client
	var err error
	if p.Stdio() {
		sc := &passmcp.StdioConfig{Command: p.Command, Args: p.Args, Env: peerEnv(p), Observe: s.recordPipe(p.Describe())}
		cfg.Stdio = sc
		client, err = passmcp.NewStdio(cctx, cfg)
	} else {
		cfg.Endpoint, cfg.Headers = p.URL, p.Headers
		cfg.HTTPClient = &http.Client{Timeout: s.Opts.CallTimeout + 5*time.Second, Transport: s.Opts.Recorder.Wrap(nil)}
		client, err = passmcp.New(cfg)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Initialize(cctx); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	tools, err := client.ListTools(cctx)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	return tools, nil
}

// peerEnv is a stdio peer's environment: the base a host passes every
// server, then the entry's own env on top.
func peerEnv(p clientconf.Server) []string {
	var env []string
	for _, n := range transport.BaseEnv {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	for _, k := range p.EnvNames {
		env = append(env, k+"="+p.Env[k])
	}
	return env
}
