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
// acknowledgement.
func checkReplies(s *Session, _ *transport.Streamable, _ func(string) context.Context, _ string, _ any) []Finding {
	return []Finding{notificationAck(s)}
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
