// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package attestation_test

import (
	"errors"
	"testing"

	upstream "satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/attestation"
)

// The forwarder is the same package under another path: the same names,
// the same values, and a statement it writes is one upstream accepts.
func TestForwarderIsTheUpstreamPackage(t *testing.T) {
	if attestation.PredicateType != upstream.PredicateType || attestation.StatementType != upstream.StatementType {
		t.Fatal("the identifiers differ")
	}
	target := attestation.Target{Transport: "http", Endpoint: "https://mcp.example.com/mcp"}
	if a, b := attestation.SubjectFor(target), upstream.SubjectFor(target); a.Name != b.Name || a.Digest["sha256"] != b.Digest["sha256"] {
		t.Fatalf("SubjectFor differs: %+v vs %+v", a, b)
	}
	if _, err := attestation.Parse([]byte(`{}`)); err == nil {
		t.Fatal("Parse accepted an empty object")
	}
	if !errors.Is(attestation.ErrNoSuchCheck, upstream.ErrNoSuchCheck) {
		t.Fatal("ErrNoSuchCheck is a different error")
	}
	var s attestation.Statement
	// Compare is upstream's and takes upstream's type; it compiles only
	// because Statement is an alias, not a new type.
	_ = attestation.Compare(&s, &s)
}
