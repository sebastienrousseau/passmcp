// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/transport"
)

// Multi Round-Trip Requests are how the 2026-07-28 revision replaced
// server-initiated sampling, elicitation and roots. A server that needs
// something from the client mid-call answers `resultType: input_required`
// with a list of client-side methods to invoke, and the client retries the
// original call with the answers attached.
//
// passmcp does not answer one. It has no user to elicit from and no model to
// sample, and inventing either would mean reporting on a conversation it
// fabricated. What it can do is judge the request, which is worth more than
// it sounds: an input_required a client cannot answer is a deadlock, and the
// agent it deadlocks will report nothing at all — the call simply never
// returns. That failure is invisible from inside the agent and obvious from
// here.
//
// The measurement is observational. passmcp cannot make a server ask for
// input; a tool that needs it is the only thing that produces one, so the
// check reports what the run happened to see and skips when it saw nothing.

// MRTRObservation is one input_required result the run received.
type MRTRObservation struct {
	// Method is the call that was interrupted, named the way the report
	// names it — "tools/call search".
	Method string `json:"method"`
	// Requests is what the server asked the client to do, carried verbatim.
	Requests []transport.InputRequest `json:"requests"`
	// State is whether the result carried a requestState. A result may
	// carry only that: the specification requires one of the two.
	State bool `json:"request_state,omitempty"`
	// ListForm is whether inputRequests arrived as an array, which no
	// revision defines.
	ListForm bool `json:"list_form,omitempty"`
}

// observe records one input_required result.
func observe(method string, ir *transport.ErrInputRequired) MRTRObservation {
	return MRTRObservation{
		Method: method, Requests: ir.Result.InputRequests,
		State: ir.Result.RequestState != "", ListForm: ir.Result.ListForm,
	}
}

// inputCapability maps each client method a server may ask for mid-call to
// the client capability that permits it. These three are the only ones the
// specification allows in inputRequests.
var inputCapability = map[string]string{
	"elicitation/create":     "elicitation",
	"sampling/createMessage": "sampling",
	"roots/list":             "roots",
}

// declaredClientCapabilities is what passmcp tells a server it supports,
// read from the same value the client sends rather than restated, so this
// check cannot drift from the wire.
func declaredClientCapabilities() map[string]bool {
	out := map[string]bool{}
	b, err := json.Marshal(passmcp.ClientCapabilities{})
	if err != nil {
		return out
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(b, &caps) == nil {
		for k := range caps {
			out[k] = true
		}
	}
	return out
}

// requestedMethods is the client-side methods one input_required asked for.
func requestedMethods(ir *transport.ErrInputRequired) []string {
	out := make([]string, 0, len(ir.Result.InputRequests))
	for _, r := range ir.Result.InputRequests {
		if m := strings.TrimSpace(r.Method); m != "" {
			out = append(out, m)
		}
	}
	return uniqueSorted(out)
}

// asInputRequired reports whether a call failed because the server wants
// client input, which is not a failure.
func asInputRequired(err error) (*transport.ErrInputRequired, bool) {
	var ir *transport.ErrInputRequired
	if err != nil && errors.As(err, &ir) {
		return ir, true
	}
	return nil, false
}

// mrtrTally sorts the input_required results by what is wrong with them.
type mrtrTally struct {
	declared                                  map[string]bool
	unanswerable, undeclared, listed, methods []string
	empty                                     int
}

// add files one interrupted call and each request it named.
func (t *mrtrTally) add(o MRTRObservation) {
	if o.ListForm {
		t.listed = append(t.listed, o.Method)
	}
	if len(o.Requests) == 0 && !o.State {
		// The worst shape, and the reason this check exists. The server
		// said it needs something and named nothing, so there is no
		// retry a client can construct: the call is unfinishable and
		// the agent waits forever.
		t.empty++
		return
	}
	for _, r := range o.Requests {
		t.addRequest(o.Method, r)
	}
}

// addRequest files one request for client input made during call method.
func (t *mrtrTally) addRequest(method string, r transport.InputRequest) {
	capability, allowed := inputCapability[r.Method]
	switch {
	case strings.TrimSpace(r.Method) == "":
		t.unanswerable = append(t.unanswerable, method+": a request with no method")
	case strings.TrimSpace(r.ID) == "":
		// Without an id the client cannot say which request each
		// answer belongs to, so a call needing two is ambiguous and
		// a call needing one is a guess.
		t.unanswerable = append(t.unanswerable, fmt.Sprintf("%s: %s with no id", method, r.Method))
	case !allowed:
		t.unanswerable = append(t.unanswerable, fmt.Sprintf("%s: %s, which is not a request a server may send mid-call", method, r.Method))
	case !t.declared[capability]:
		t.undeclared = append(t.undeclared, fmt.Sprintf("%s: %s", method, r.Method))
	default:
		t.methods = append(t.methods, r.Method)
	}
}

// checkMRTR judges the input_required results the run saw.
func checkMRTR(s *Session) Finding {
	c := s.check("protocol.mrtr", "Requests for client input are answerable")

	if len(s.MRTR) == 0 {
		if s.Stateless() {
			return c.skip("no call asked for client input, so there was nothing to judge; passmcp cannot make a server ask")
		}
		return c.skip("Multi Round-Trip Requests are a " + transport.V20260728 + " mechanism and no call asked for client input")
	}

	t := mrtrTally{declared: declaredClientCapabilities()}
	for _, o := range s.MRTR {
		t.add(o)
	}
	unanswerable, undeclared, listed, methods, empty := t.unanswerable, t.undeclared, t.listed, t.methods, t.empty

	c = c.ev(observedCalls(s.MRTR)...)

	if empty > 0 {
		return c.fail(Critical,
			fmt.Sprintf("%s answered input_required and named no request", plural(empty, "call")),
			"list what you need in inputRequests, or carry the context in requestState. A client that is told input is required and not told what to supply cannot retry, so the call never completes and the agent waits on it rather than failing — which is worse than an error, because nothing is reported")
	}
	if len(listed) > 0 {
		return c.fail(Major,
			"inputRequests was sent as a list for "+list(uniqueSorted(listed))+"; the specification defines an object keyed by request id",
			"send inputRequests as an object whose keys are your request ids and whose values are the requests. A client following the specification reads that shape and no other, so it finds nothing to answer here")
	}
	if len(unanswerable) > 0 {
		sort.Strings(unanswerable)
		return c.fail(Major,
			"a request for client input cannot be answered: "+list(unanswerable),
			"key every entry in inputRequests by an id, and ask only for elicitation/create, sampling/createMessage or roots/list. The id is how the client says which answer belongs to which request when it retries the call")
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return c.fail(Major,
			"asked for client input the client did not declare support for: "+list(undeclared),
			"read the client capabilities on each request and ask only for what it declared; the specification forbids asking otherwise. A client without elicitation has no way to put the question to anyone, so the call cannot finish")
	}
	if len(methods) == 0 {
		return c.pass(fmt.Sprintf("%s asked to be retried with requestState only, in the shape the specification defines",
			plural(len(s.MRTR), "call")))
	}
	return c.pass(fmt.Sprintf("%s asked for client input, and every request was keyed, permitted and declared (%s)",
		plural(len(s.MRTR), "call"), list(uniqueSorted(methods))))
}

// observedCalls names the interrupted calls, for the evidence line.
func observedCalls(obs []MRTRObservation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Method)
	}
	return uniqueSorted(out)
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
