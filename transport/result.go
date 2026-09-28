// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Result types defined by the 2026-07-28 revision.
const (
	// ResultComplete means the result holds the final content. It is also
	// what an absent resultType means, for servers on earlier revisions.
	ResultComplete = "complete"
	// ResultInputRequired means the server needs something from the client
	// before it can finish, and the client must retry the original call
	// with the answers attached. This is the Multi Round-Trip Request
	// pattern that replaced server-initiated sampling, elicitation and
	// roots.
	ResultInputRequired = "input_required"
)

// ResultType reports the resultType of a JSON-RPC result. An absent field
// means "complete": servers on revisions before 2026-07-28 do not send one,
// and the specification requires clients to read that as a finished result.
func ResultType(result json.RawMessage) string {
	if len(result) == 0 {
		return ResultComplete
	}
	var probe struct {
		ResultType string `json:"resultType"`
	}
	if json.Unmarshal(result, &probe) != nil || probe.ResultType == "" {
		return ResultComplete
	}
	return probe.ResultType
}

// InputRequest is one thing a server asked the client for mid-call.
type InputRequest struct {
	// ID correlates this request with the response the client attaches to
	// the retry.
	ID string `json:"id"`
	// Method is the client-side method the server is invoking, such as
	// elicitation/create.
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// InputRequiredResult is the body of a result whose resultType is
// input_required.
//
// On the wire, inputRequests is an object keyed by server-assigned id. It
// is decoded into a list, sorted by id with each request's ID set from its
// key, so callers have one shape to read.
type InputRequiredResult struct {
	ResultType    string          `json:"resultType"`
	InputRequests []InputRequest  `json:"inputRequests"`
	Meta          json.RawMessage `json:"_meta,omitempty"`
	// RequestState is the opaque string the server wants echoed on retry.
	// A result may carry it and no requests at all.
	RequestState string `json:"requestState,omitempty"`
	// ListForm is true when the server sent inputRequests as a JSON array,
	// which no revision defines. The requests are still read, so a report
	// can say what was asked, but a client following the specification
	// would not find them.
	ListForm bool `json:"-"`
}

// UnmarshalJSON reads inputRequests in the object form the specification
// defines, and in the array form some servers send instead.
func (r *InputRequiredResult) UnmarshalJSON(b []byte) error {
	type plain InputRequiredResult
	var raw struct {
		plain
		InputRequests json.RawMessage `json:"inputRequests"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*r = InputRequiredResult(raw.plain)
	r.InputRequests = nil
	switch in := bytes.TrimSpace(raw.InputRequests); {
	case len(in) == 0 || string(in) == "null":
	case in[0] == '[':
		if err := json.Unmarshal(in, &r.InputRequests); err != nil {
			return err
		}
		r.ListForm = true
	default:
		var byID map[string]InputRequest
		if err := json.Unmarshal(in, &byID); err != nil {
			return err
		}
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			req := byID[id]
			req.ID = id
			r.InputRequests = append(r.InputRequests, req)
		}
	}
	return nil
}

// ErrInputRequired reports a result the caller must answer before the
// original request can complete. passmcp surfaces it rather than answering:
// a diagnostic has no user to elicit from and no model to sample, and
// inventing either would mean reporting on a conversation it fabricated.
type ErrInputRequired struct {
	Method string
	Result InputRequiredResult
}

func (e *ErrInputRequired) Error() string {
	methods := make([]string, 0, len(e.Result.InputRequests))
	for _, r := range e.Result.InputRequests {
		methods = append(methods, r.Method)
	}
	return fmt.Sprintf("transport: %s needs client input before it can complete (%d request(s): %v)", e.Method, len(e.Result.InputRequests), methods)
}

// AsInputRequired decodes an input_required result, if that is what it is.
func AsInputRequired(method string, result json.RawMessage) (*ErrInputRequired, bool) {
	if ResultType(result) != ResultInputRequired {
		return nil, false
	}
	var out InputRequiredResult
	if err := json.Unmarshal(result, &out); err != nil {
		// It claimed input_required but the body does not decode. Let the
		// ordinary result path report that rather than asserting a shape
		// that is not there.
		return nil, false //nolint:nilerr // a malformed body is not an input request
	}
	return &ErrInputRequired{Method: method, Result: out}, true
}

// UnsupportedVersionError is the -32022 error a 2026-07-28 server returns
// when it does not implement the version a request asked for. It carries
// the versions it does support, which is what makes renegotiation possible
// without guessing.
type UnsupportedVersionError struct {
	Requested string
	Supported []string
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("transport: server does not support protocol version %q (it supports %v)", e.Requested, e.Supported)
}

// MissingCapabilityError is the -32021 error a server returns when a
// request needed a client capability the request did not declare.
type MissingCapabilityError struct {
	Required []string
}

func (e *MissingCapabilityError) Error() string {
	return fmt.Sprintf("transport: the server needs client capabilities this request did not declare: %v", e.Required)
}

// HeaderMismatchError is the -32020 error a server returns when a mirrored
// header disagreed with the body, or a required one was missing.
type HeaderMismatchError struct{ Message string }

func (e *HeaderMismatchError) Error() string {
	return "transport: the server rejected the routing headers: " + e.Message
}

// AsProtocolError converts a JSON-RPC error into the typed 2026-07-28 error
// it represents, or returns it unchanged. Recognising these is also how a
// client tells a modern server from a legacy one: both answer 400, but only
// a modern one explains itself in the body.
func AsProtocolError(requested string, e *RPCError) error {
	if e == nil {
		return nil
	}
	switch e.Code {
	case CodeUnsupportedProtocolVersion:
		out := &UnsupportedVersionError{Requested: requested}
		var data struct {
			Supported []string `json:"supported"`
		}
		if json.Unmarshal(e.Data, &data) == nil {
			out.Supported = data.Supported
		}
		return out
	case CodeMissingClientCapability:
		out := &MissingCapabilityError{}
		var data struct {
			RequiredCapabilities []string `json:"requiredCapabilities"`
		}
		if json.Unmarshal(e.Data, &data) == nil {
			out.Required = data.RequiredCapabilities
		}
		return out
	case CodeHeaderMismatch:
		return &HeaderMismatchError{Message: e.Message}
	}
	return e
}

// IsModernError reports whether an error body carries a JSON-RPC error a
// 2026-07-28 server would send. The backward-compatibility rule turns on
// this: a 400 with a recognised modern error means the server speaks the
// new revision and the client should correct its request, while a 400 with
// an empty or unrecognised body means it should fall back to initialize.
func IsModernError(body []byte) (*RPCError, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var out Response
	if json.Unmarshal(body, &out) != nil || out.Error == nil {
		// A body that is not a JSON-RPC error is exactly the legacy signal
		// this predicate exists to report.
		return nil, false //nolint:nilerr // a predicate, not an error path
	}
	switch out.Error.Code {
	case CodeHeaderMismatch, CodeMissingClientCapability, CodeUnsupportedProtocolVersion, CodeMethodNotFound:
		return out.Error, true
	}
	return nil, false
}
