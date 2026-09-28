// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"testing"
)

func TestMainCallsExecuteWithSignalContext(t *testing.T) {
	orig := execute
	defer func() { execute = orig }()
	var got context.Context
	var live bool
	execute = func(ctx context.Context) { got, live = ctx, ctx.Err() == nil }
	main()
	if got == nil || !live {
		t.Fatalf("execute not called with a live context: %v", got)
	}
	if got.Err() == nil {
		t.Error("deferred stop should cancel the signal context after main returns")
	}
}
