// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Command passmcp is the entry point for the passmcp CLI.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"satellion.com/passmcp/cmd"
)

// execute is indirected so tests can run main without the real CLI
// parsing the test binary's arguments.
var execute = cmd.ExecuteContext

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	execute(ctx)
}
