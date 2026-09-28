// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace_test

import (
	"context"
	"fmt"

	"satellion.com/passmcp/trace"
)

// A diagnostic makes dozens of requests across nine phases, and a finding
// is only worth something if you can get back to the exchange behind it.
// Ensure puts an id on the context once; everything downstream reads the
// same one.
func ExampleEnsure() {
	ctx := trace.Ensure(context.Background())

	id := trace.FromContext(ctx)
	fmt.Println("id is set:", id != "")
	fmt.Println("stable across reads:", id == trace.FromContext(ctx))

	// Ensure is idempotent: a context that already carries an id keeps it,
	// so a nested call cannot orphan the requests made above it.
	fmt.Println("idempotent:", trace.FromContext(trace.Ensure(ctx)) == id)
	// Output:
	// id is set: true
	// stable across reads: true
	// idempotent: true
}

// WithID adopts an id that came from somewhere else — a CI job, an
// upstream request header — so a passmcp run can be correlated with whatever
// asked for it.
func ExampleWithID() {
	ctx := trace.WithID(context.Background(), "build-4821")

	fmt.Println(trace.FromContext(ctx))
	// Output:
	// build-4821
}
