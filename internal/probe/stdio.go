// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// Everything here exists because a stdio server is a different subject, not
// a thinner one.
//
// Most MCP servers are programs, not endpoints, so a diagnostic that only
// speaks HTTP cannot look at most of what it claims to diagnose. The risk
// in adding the transport is subtler than not having it: a run that quietly
// reports fewer checks reads as a better result. Nine phases and eighty-one
// checks on the website, thirty findings in the report, and no statement
// anywhere that twelve of them never ran.
//
// So every check that does not apply over a pipe says so, by name, as a
// skipped finding — and every check that does apply is made to work rather
// than skipped for convenience.

// overStdio reports whether this run is talking to a child process.
func (s *Session) overStdio() bool { return s.Pipe != nil }

// observesTheProcess reports whether a phase's stdio form looks at the
// child process rather than at the protocol.
//
// Such a phase always has an answer, so a blocked run still runs it — and a
// blocked run is when "the process exited" or "it wrote a banner to stdout"
// is the finding that explains every other one.
func (s *Session) observesTheProcess(p Phase) bool {
	return s.overStdio() && p.RunStdio != nil
}

// command renders the program passmcp ran, for a report.
func (s *Session) command() string {
	if s.Opts.Stdio == nil {
		return ""
	}
	parts := append([]string{s.Opts.Stdio.Command}, s.Opts.Stdio.Args...)
	return strings.Join(parts, " ")
}

// --- raw exchanges over either transport -----------------------------------

// rawSend is one deliberately unusual message, in the terms both transports
// share.
type rawSend struct {
	Request     *transport.Request
	Body        []byte
	SkipDialect bool
	// AnyMessage accepts a reply whose id does not match the request's.
	//
	// It only affects stdio, where replies are matched by id and an
	// unmatched one would otherwise be dropped — turning "the server
	// echoed the wrong id" into "the server did not answer", which is a
	// different and less true finding. Over HTTP the answer arrives on the
	// request's own response, so there is nothing to match.
	AnyMessage bool
}

// rawReply is what came back.
type rawReply struct {
	Response *transport.Response
	// Body is the response body, or over a pipe the line the server wrote.
	Body []byte
	// Status and ContentType are the HTTP view. HTTP says whether they mean
	// anything: over a pipe they are zero, and a check that reads them
	// without asking would conclude "HTTP 0".
	Status      int
	ContentType string
	HTTP        bool
}

// rawExchange sends one raw message over whichever transport is in use.
func (s *Session) rawExchange(ctx context.Context, send rawSend) (rawReply, error) {
	if tr, ok := s.Client.HTTP(); ok {
		raw, err := tr.Do(ctx, transport.RawOptions{
			Request: send.Request, Body: send.Body, SkipDialect: send.SkipDialect,
		})
		if err != nil {
			return rawReply{HTTP: true}, err
		}
		return rawReply{
			Response: raw.Response, Body: raw.Body,
			Status: raw.Status, ContentType: raw.ContentType, HTTP: true,
		}, nil
	}
	res, err := s.Pipe.Exchange(ctx, transport.StdioExchange{
		Request: send.Request, Body: send.Body,
		SkipDialect: send.SkipDialect, AnyMessage: send.AnyMessage,
	})
	if err != nil {
		return rawReply{}, err
	}
	return rawReply{Response: res.Response, Body: res.Line}, nil
}

// nextID reserves a JSON-RPC id on whichever transport is in use.
func (s *Session) nextID() int64 { return s.Client.Conn().NextID() }

// --- the phases that change shape over a pipe ------------------------------

// phaseNetStdio replaces the connectivity phase.
//
// There is no name to resolve, no port to reach and no certificate to
// check. What takes their place is the question those checks were really
// asking — is the thing on the other end there — plus the one an HTTP run
// never has to ask: what did passmcp hand to a program it is about to run.
func phaseNetStdio(ctx context.Context, s *Session) []Finding {
	var out []Finding

	c := s.check("stdio.process", "Server process is running")
	cmd := s.Opts.Recorder.Redactor.String(s.command())
	if exited, werr := s.Pipe.Exited(); exited {
		detail := "the server exited before the first request"
		if werr != nil {
			detail += ": " + werr.Error()
		}
		if msg := strings.TrimSpace(s.Pipe.Stderr()); msg != "" {
			detail += "; stderr: " + truncate(msg, 300)
		}
		out = append(out, c.ev(cmd).fail(Critical, detail,
			"run the command yourself and read its output: a server that exits immediately is usually missing an argument, a file or an environment variable"))
		s.blocked = "the server process exited"
		// The launch command is most worth reading when the launch failed.
		return append(out, launchConfigFindings(s)...)
	}
	out = append(out, c.ev(cmd).pass(fmt.Sprintf("pid %d", s.Pipe.PID())))

	// What the program is, before anything about how it behaves. Read off
	// the file, so it is the one part of the report the server cannot
	// influence by answering differently.
	out = append(out, checkSupplyChain(s)...)

	// Not a judgement on the server: a statement of what passmcp passed it,
	// because a server that behaves differently in this run than in the
	// operator's own shell almost always differs here. An HTTP run has no
	// equivalent to get wrong.
	c = s.check("stdio.environment", "Environment handed to the server")
	names := append([]string{}, transport.BaseEnv...)
	if s.Opts.Stdio != nil {
		names = append(names, s.Opts.Stdio.PassEnv...)
	}
	switch {
	case s.Opts.Stdio != nil && s.Opts.Stdio.Env != nil:
		out = append(out, c.info(fmt.Sprintf("%d variable(s), set explicitly", len(s.Opts.Stdio.Env))))
	case s.Opts.Stdio != nil && len(s.Opts.Stdio.PassEnv) > 0:
		out = append(out, c.info("a fixed base plus "+strings.Join(s.Opts.Stdio.PassEnv, ", ")))
	default:
		out = append(out, c.ev(strings.Join(names, " ")).info(
			"a fixed base only; nothing else was forwarded. A server that needs a credential in its environment must be given it by name"))
	}
	return append(out, launchConfigFindings(s)...)
}

// phaseResilienceStdio replaces the resilience phase.
//
// Over HTTP resilience means recovering from a lost session or an expired
// token. A pipe has neither: the connection is the session, and there is no
// token. What it has instead is a process, and the questions worth asking
// at the end of a run are whether it is still there, whether it kept the
// transport clean, and what it said on the way.
func phaseResilienceStdio(ctx context.Context, s *Session) []Finding {
	var out []Finding

	// A long run of one call, when asked for. Before the witness stops,
	// so what the server reaches for under sustained use is still seen.
	out = append(out, checkSoak(ctx, s)...)

	// What the server did after its handshake, from the samples taken
	// while every other phase ran. Stopped before the process is judged.
	out = append(out, checkWitness(s)...)

	// Its dependencies failed on purpose, when asked for. Before the
	// liveness check, so a server that dies of it is judged alive or not
	// afterwards.
	out = append(out, checkUpstreamDown(ctx, s)...)

	c := s.check("stdio.alive", "Server survived the run")
	if exited, werr := s.Pipe.Exited(); exited {
		detail := "the server exited during the run"
		if werr != nil {
			detail = "the server exited during the run: " + werr.Error()
		}
		advice := "a host keeps one process for the whole session, so an exit mid-session ends every conversation with it. Find what the last request was and handle it without dying"
		if msg := strings.TrimSpace(s.Pipe.Stderr()); msg != "" {
			out = append(out, c.ev(truncate(msg, 400)).fail(Major, detail, advice))
		} else {
			out = append(out, c.fail(Major, detail+", and said nothing on stderr", advice))
		}
	} else {
		out = append(out, c.pass("still running after the last request"))
	}

	// Where it went while it was doing all that. Here rather than in an
	// earlier phase because the answer is only complete once the server
	// has had the whole run to reach for something.
	out = append(out, checkEgress(s)...)

	// And whether it went looking for anything on the way.
	out = append(out, checkCanaries(s)...)

	// The stream is the wire. This is the single most common way a stdio
	// server is broken, and the symptom a host reports — a hang, or a parse
	// error naming a line the operator never wrote — never names the cause.
	c = s.check("stdio.stdout_clean", "Nothing but MCP messages on stdout")
	if n, sample := s.Pipe.Noise(); n > 0 {
		out = append(out, c.ev(sample).fail(Major,
			fmt.Sprintf("%s written to stdout that was not a JSON-RPC message, first: %q", plural(n, "line"), truncate(sample, 200)),
			"send logs to stderr. stdout is the transport: a single print statement, a banner or a progress bar corrupts the framing and the client cannot recover"))
	} else {
		out = append(out, c.pass("no stray output"))
	}

	// Logging to stderr is correct behaviour, so this reports rather than
	// judges. It is here because a server that failed a check often
	// explained why on stderr, and nothing else in the report carries that.
	c = s.check("stdio.stderr", "What the server logged")
	if msg := strings.TrimSpace(s.Pipe.Stderr()); msg != "" {
		lines := strings.Count(msg, "\n") + 1
		out = append(out, c.ev(truncate(msg, 2000)).info(fmt.Sprintf("%s on stderr", plural(lines, "line"))))
	} else {
		out = append(out, c.info("nothing on stderr"))
	}
	return out
}

// settleEraStdio decides which generation a child process speaks.
//
// The HTTP probe leans on a status code: the stateless revision answers an
// unimplemented RPC with 404 carrying -32601, while a handshake-era server
// answers the same -32601 at 200, so the status is the whole signal. A pipe
// has no status, so that distinction is not available and pretending
// otherwise would label every legacy server as current.
//
// What is left is honest and narrower: a server that answers server/discover
// speaks the stateless revision. Anything else is treated as handshake-era,
// and the handshake that follows settles it — a stateless server that omits
// the optional RPC is the one case this cannot name, and the reason says so.
func (s *Session) settleEraStdio(ctx context.Context) {
	if s.Era != nil || s.Opts.SkipEraCheck {
		return
	}
	caps, err := json.Marshal(struct{}{})
	if err != nil {
		return
	}
	restore := s.Pipe.Dialect()
	defer func() {
		s.Pipe.SetDialect(restore)
		s.Pipe.Reset()
	}()
	s.Pipe.SetDialect(&transport.Stateless{
		ProtocolVersion: passmcp.StatelessVersions[0],
		ClientInfo:      transport.Implementation{Name: "passmcp", Version: s.Opts.Version},
		Capabilities:    caps,
	})

	var disc passmcp.DiscoverResult
	cctx := telemetry.WithPhase(ctx, "handshake", "stateless probe")
	if s.Opts.CallTimeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(cctx, s.Opts.CallTimeout)
		defer cancel()
	}
	if err := s.Pipe.Call(cctx, "server/discover", map[string]any{}, &disc); err == nil {
		s.Era = &passmcp.Negotiation{
			Era: passmcp.EraStateless, Version: passmcp.StatelessVersions[0], Discovered: &disc,
			Reason: "it answered server/discover",
		}
		return
	}
	s.Era = &passmcp.Negotiation{
		Era: passmcp.EraSession,
		Reason: "it did not answer server/discover; over a pipe there is no status code to tell " +
			"an unimplemented method from an older server, so the handshake decides",
	}
}

// recordPipe wires the transport's observer to the run's recorder, so a
// stdio finding cites evidence the way an HTTP one does.
func (s *Session) recordPipe(target string) func(context.Context, transport.StdioMessage) {
	return func(ctx context.Context, m transport.StdioMessage) {
		s.Opts.Recorder.RecordPipe(ctx, target, m.Sent, m.Received, m.Duration, m.Err)
	}
}

// httpOnlyChecks are the conformance probes that are about HTTP rather than
// about MCP, with the reason each has no form over a pipe.
//
// They are reported as skipped, by id, rather than left out. A report that
// silently contains fewer checks than the documentation promises is a
// report that reads as a better result than it is.
var httpOnlyChecks = []struct{ id, title, why string }{
	{"protocol.accept_header", "Request without Accept header",
		"Accept is an HTTP header; a pipe has no headers to omit"},
	{"protocol.get_stream", "GET on the MCP endpoint",
		"there is no GET over a pipe, and no second channel a client could open"},
	{"protocol.bogus_session", "Unknown session id is rejected",
		"sessions are carried in an HTTP header; over a pipe the connection is the session, so there is no id to forge"},
	{"protocol.version_header", "Bad MCP-Protocol-Version is rejected",
		"the protocol version travels in an HTTP header on this revision; over a pipe it travels in the body, which the dialect already builds"},
	{"protocol.origin", "A foreign Origin is rejected",
		"Origin is a browser's HTTP header, and DNS rebinding reaches an HTTP listener; a pipe has neither"},
}

// skipHTTPOnly names every conformance check that cannot be made over a
// pipe, and why.
func (s *Session) skipHTTPOnly() []Finding {
	out := make([]Finding, 0, len(httpOnlyChecks))
	for _, h := range httpOnlyChecks {
		out = append(out, s.check(h.id, h.title).skip("not applicable over stdio: "+h.why))
	}
	return out
}

// stdioSilence is how long a raw probe waits for an answer that may never
// come.
//
// Over HTTP a server that ignores a malformed body still answers the
// request, so there is always a response to read. Over a pipe the same
// server writes nothing, and the probe has to decide when to call that
// silence. Three seconds is generous for a process on this machine that
// has already answered several calls, and short enough that four probes
// against a silent server do not add a minute to the run.
const stdioSilence = 3 * time.Second

// stdioDeadline bounds one raw probe over a pipe. Over HTTP it changes
// nothing: the transport's own timeout already applies.
func (s *Session) stdioDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if !s.overStdio() {
		return ctx, func() {}
	}
	d := stdioSilence
	if s.Opts.CallTimeout > 0 && s.Opts.CallTimeout < d {
		d = s.Opts.CallTimeout
	}
	return context.WithTimeout(ctx, d)
}

// --- custody, after the process is gone --------------------------------

// custodyFindings reports what shutting the server down took, and what
// survived it.
//
// These two run after the phases rather than inside one, because neither
// is observable while the server is up: "it stopped when its input closed"
// needs the input to have been closed, and "nothing outlived it" needs it
// to have been reaped first. The resilience phase adopts them, since that
// is where the rest of the end-of-run process questions live.
func (s *Session) custodyFindings() []Finding {
	if s.Pipe == nil {
		return nil
	}
	c := s.Pipe.Custody()
	var out []Finding

	// Closing stdin is how the specification says to stop a stdio server,
	// and a host does exactly this between conversations. One that has to
	// be signalled instead is one that accumulates on a developer's
	// machine, a process per session, until something runs out.
	clean := s.check("stdio.clean_exit", "Server stopped when its input closed")
	switch {
	case c.AlreadyExited:
		out = append(out, clean.skip("the server was already gone before shutdown began; stdio.alive carries that"))
	case c.Forced:
		out = append(out, clean.fail(Major,
			fmt.Sprintf("the server was still running after its stdin closed and had to be sent %s", c.Signalled),
			"exit when stdin reaches EOF. A host closes the pipe to end a session and does not wait long; "+
				"a server that ignores it is killed, loses whatever it had not flushed, and leaves the host "+
				"to do the same thing again next time"))
	default:
		out = append(out, clean.pass("exited on its own when stdin closed"))
	}

	// The question no other diagnostic asks, because no other diagnostic
	// owns the process: when the server went, did everything it started
	// go with it.
	zombie := s.check("stdio.no_zombie", "The server left nothing running")
	switch {
	case !c.Supported:
		out = append(out, zombie.skip("this platform has no process group to inspect, so passmcp cannot tell and will not guess"))
	case c.Err != nil:
		out = append(out, zombie.info("the server's process group could not be inspected: "+c.Err.Error()))
	case c.Forced:
		out = append(out, zombie.skip("the server had to be signalled, so its whole group was ended with it and "+
			"what it left behind cannot be told apart from what the signal stopped"))
	case c.Orphans:
		out = append(out, zombie.fail(Major,
			"the server exited but processes it started were still running in its process group",
			"reap what you spawn. A worker that outlives its server holds whatever it was given — a port, a lock, "+
				"the credentials from its environment — with nothing left to shut it down; passmcp killed this one, "+
				"and a host will not"))
	default:
		out = append(out, zombie.pass("its process group was empty once it exited"))
	}
	return out
}

// adoptCustody attaches the custody findings to the resilience phase.
//
// A phase that was never selected has no result to attach to, and one that
// was skipped has already said why; in both cases the checks simply did
// not run, which is the same answer the rest of the report gives.
func (s *Session) adoptCustody() {
	findings := s.custodyFindings()
	if len(findings) == 0 {
		return
	}
	for i := range s.Results {
		if s.Results[i].Name != "resilience" || s.Results[i].Status == Skip {
			continue
		}
		for j := range findings {
			findings[j].Phase = "resilience"
			if s.Opts.Progress != nil {
				s.Opts.Progress("resilience", &findings[j])
			}
		}
		s.Results[i].Findings = append(s.Results[i].Findings, findings...)
		s.Results[i].Status = worst(s.Results[i].Findings)
		s.Results[i].Summary = summarize("resilience", s, s.Results[i])
		return
	}
}
