// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

// The fake server's HTTP helpers: bearer validation, the 401 challenge and
// the reply writer, kept apart from fake_test.go's request handler.

import (
	"fmt"
	"net/http"
	"strings"
)

func (f *fakeServer) validToken(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" || f.q.rejectCredentials {
		return false
	}
	if f.q.wrongAudience != "" && tok == f.q.wrongAudience {
		return f.q.wrongAudienceAccepted
	}
	if f.acceptAnyToken {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[tok]
}

func (f *fakeServer) unauthorized(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	garbage := strings.HasPrefix(tok, "passmcp-invalid-")
	status := 401
	if garbage && f.q.garbageStatus != 0 {
		status = f.q.garbageStatus
	}
	if !garbage && tok == "" && f.q.firstContactStatus != 0 {
		status = f.q.firstContactStatus
	}
	if tok != "" && tok == f.q.wrongAudience && f.q.wrongAudienceStatus != 0 {
		status = f.q.wrongAudienceStatus
	}
	hdr := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`, f.srv.URL)
	if f.q.challenge != "" {
		hdr = f.q.challenge
	}
	if f.noChallenge || hdr == "-" || (garbage && f.q.garbageNoHeader) {
		hdr = ""
	}
	if hdr != "" && status == 401 {
		w.Header().Set("WWW-Authenticate", hdr)
		if f.q.dpopNonce != "" {
			w.Header().Set("DPoP-Nonce", f.q.dpopNonce)
		}
	}
	if status/100 == 2 && garbage {
		// Pretend the garbage token was fine: fall through to the handler.
		return
	}
	w.WriteHeader(status)
	if status/100 == 2 {
		_, _ = w.Write([]byte("not a result"))
	}
}

// writeReply writes one JSON-RPC message as the reply to a request, with
// the content type and framing the quirks ask for.
func (f *fakeServer) writeReply(w http.ResponseWriter, msg string) {
	switch {
	case f.q.sseReplies:
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
		return
	case f.q.replyContentType == "-":
		// A nil value is how net/http is told not to sniff one.
		w.Header()["Content-Type"] = nil
	case f.q.replyContentType != "":
		w.Header().Set("Content-Type", f.q.replyContentType)
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	_, _ = w.Write([]byte(msg))
}
