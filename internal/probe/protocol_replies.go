// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"fmt"
	"net/http"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/transport"
)

// checkReplies judges how the endpoint answers over the Streamable HTTP
// binding, as distinct from what it answers: the status and body of an
// acknowledgement, the label on a reply, and whether a session the server
// issued is one it requires.
func checkReplies(s *Session, tr *transport.Streamable, pctx func(string) context.Context, live string, liveParams any) []Finding {
	return []Finding{
		notificationAck(s),
		probeContentType(pctx("content type"), s, tr, live, liveParams),
		probeMissingSession(pctx("missing session"), s, tr, live, liveParams),
	}
}

// probeContentType is the protocol.content_type verdict: a reply to a
// request is labelled application/json or text/event-stream.
//
// It sends one liveness call, the same read-only request protocol.ping
// makes, and reads the label on the reply. The transport reads a body
// that decodes whatever its label, so a mislabelled server can pass every
// other check; this is where the label itself is judged.
func probeContentType(ctx context.Context, s *Session, tr *transport.Streamable, live string, liveParams any) Finding {
	c := s.check("protocol.content_type", "Replies are JSON or an event stream")
	id := tr.NextID()
	hrep, err := tr.Do(ctx, transport.RawOptions{Request: &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)}})
	return contentTypeVerdict(c, live, hrep, err)
}

// contentTypeVerdict judges the label on one reply. Anything else is
// major: the transport allows only the two, and a client that dispatches
// on the header, as the reference SDKs do, refuses the reply outright.
func contentTypeVerdict(c *check, live string, hrep *transport.RawResult, err error) Finding {
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case hrep.Status != http.StatusOK:
		return c.info(fmt.Sprintf("HTTP %d to %s; no reply to judge", hrep.Status, live))
	case hrep.ContentType == "application/json", hrep.ContentType == "text/event-stream":
		return c.pass(hrep.ContentType)
	}
	ct := hrep.ContentType
	if ct == "" {
		// A header that does not parse is still named, not called absent.
		ct = hrep.Header.Get("Content-Type")
	}
	got := (&transport.ContentTypeError{ContentType: truncate(ct, 60)}).Got()
	return c.fail(Major,
		fmt.Sprintf("the reply to %s: expected application/json or text/event-stream, %s", live, got),
		"label a reply to a request Content-Type: application/json for a single JSON object, or text/event-stream for a stream; the Streamable HTTP transport allows nothing else")
}

// probeMissingSession is the protocol.missing_session verdict: once the
// server has issued a session id, a request without one is refused.
//
// The request is the liveness call, carrying the operator's credentials
// and the protocol version but no Mcp-Session-Id. It goes over the
// client's transport rather than Bare (ADR 0001) on purpose: without
// credentials a protected server answers 401 whatever the session, and
// the refusal could not be attributed to the missing id.
func probeMissingSession(ctx context.Context, s *Session, tr *transport.Streamable, live string, liveParams any) Finding {
	c := s.check("protocol.missing_session", "A request without Mcp-Session-Id is rejected")
	switch {
	case s.Stateless():
		return c.skip("the " + passmcp.StatelessVersions[0] + " revision has no sessions, so there is no session id to leave out")
	case !s.SessionID:
		return c.skip("the server issued no session id at initialize, so every request it serves already carries none")
	}
	// Do adopts any session id a reply hands out. One handed to a request
	// that had none is not the session this run is using.
	defer tr.SetSessionID(tr.SessionID())
	id := tr.NextID()
	hrep, err := tr.Do(ctx, transport.RawOptions{
		Request:     &transport.Request{JSONRPC: "2.0", ID: &id, Method: live, Params: liveJSON(liveParams)},
		OmitSession: true,
	})
	return missingSessionVerdict(c, hrep, err)
}

// missingSessionVerdict judges the answer to a request without the
// session id. The transport says a server that requires a session SHOULD
// answer such a request with 400, so serving it is a warning rather than
// a failure; any other refusal still shows the property, and says which
// status it used.
func missingSessionVerdict(c *check, hrep *transport.RawResult, err error) Finding {
	switch {
	case err != nil:
		return c.info("request failed: " + truncate(err.Error(), 100))
	case hrep.Status == http.StatusBadRequest:
		return c.pass("400 for a request without Mcp-Session-Id")
	case hrep.Status/100 == 4:
		return c.pass(fmt.Sprintf("HTTP %d for a request without Mcp-Session-Id (the specification asks for 400)", hrep.Status))
	case hrep.Status/100 == 2:
		return c.warn("served a request without Mcp-Session-Id, although the server issued one at initialize",
			"answer a request that lacks the session id with 400 Bad Request, or stop issuing one if the server does not need sessions")
	default:
		return c.info(fmt.Sprintf("HTTP %d; neither served nor refused", hrep.Status))
	}
}

// initializedMethod is the notification a handshake ends with.
const initializedMethod = "notifications/initialized"

// notificationAck is the protocol.notification_ack verdict: the reply to
// the notifications/initialized the handshake sent was 202 Accepted with
// no body.
//
// The transport says a server that accepts a notification MUST answer
// 202 Accepted with no body. The handshake already sent one, and its
// exchange is in the recording, so that is the evidence: sending a second
// notification to judge would be a request with no purpose but this
// check, and one a server is entitled to find odd.
func notificationAck(s *Session) Finding {
	c := s.check("protocol.notification_ack", "notifications/initialized is acknowledged with 202")
	if s.Stateless() {
		return c.skip("the " + passmcp.StatelessVersions[0] + " revision has no initialize handshake, so no " +
			initializedMethod + " was sent to acknowledge")
	}
	e, ok := lastNotification(s.Opts.Recorder, initializedMethod)
	if !ok {
		return c.skip("no " + initializedMethod + " is in this run's recording: the handshake did not run, " +
			"or its exchange was dropped to stay within the event limit")
	}
	// Cited by hand: the exchange was made before this check opened, so
	// the range the builder would attach is empty.
	c.ev(fmt.Sprintf("req#%d", e.Seq))
	return ackVerdict(c, e)
}

// lastNotification is the most recent recorded exchange that sent the
// notification method.
func lastNotification(rec *telemetry.Recorder, method string) (telemetry.Event, bool) {
	evs := rec.Events()
	for i := len(evs) - 1; i >= 0; i-- {
		if r := evs[i].RPC; r != nil && r.Notification && r.Method == method {
			return evs[i], true
		}
	}
	return telemetry.Event{}, false
}

// ackVerdict judges one recorded acknowledgement. A wrong 2xx is minor:
// most clients ignore what comes back to a notification, but one that
// reads it is owed what the transport promised. A refusal is major: the
// server rejected the message that completes the handshake.
func ackVerdict(c *check, e telemetry.Event) Finding {
	const advice = "answer an accepted notification with 202 Accepted and no body; the Streamable HTTP transport requires exactly that"
	switch {
	case e.Error != "":
		return c.info("the notification's exchange failed: " + truncate(e.Error, 100))
	case e.Status == http.StatusAccepted && e.ResponseBytes == 0:
		return c.pass("202 Accepted, empty body")
	case e.Status == http.StatusAccepted:
		return c.fail(Minor, fmt.Sprintf("202 Accepted with a body of %d bytes; the transport requires none", e.ResponseBytes), advice)
	case e.Status/100 == 2:
		return c.fail(Minor, fmt.Sprintf("HTTP %d %s where the transport requires 202 Accepted with no body", e.Status, bodyNote(e)), advice)
	default:
		return c.fail(Major, fmt.Sprintf("HTTP %d: the server refused the notification that completes the handshake", e.Status), advice)
	}
}

// bodyNote says what an acknowledgement carried.
func bodyNote(e telemetry.Event) string {
	if e.ResponseBytes == 0 {
		return "with no body"
	}
	if e.ContentType == "" {
		return fmt.Sprintf("with a body of %d bytes", e.ResponseBytes)
	}
	return fmt.Sprintf("with a body of %d bytes (%s)", e.ResponseBytes, truncate(e.ContentType, 60))
}
