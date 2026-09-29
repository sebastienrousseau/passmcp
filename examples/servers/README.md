<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Servers that fail on purpose

A local MCP server that carries one deliberate defect at a time, so you can
see what passmcp catches without pointing it at anybody's real server.

```sh
go run ./examples/servers -list                   # every flaw and the check that catches it
go run ./examples/servers -flaw toxic-pair &      # serve one on 127.0.0.1:7777
passmcp check http://127.0.0.1:7777/mcp
```

`-flaw baseline` (the default) serves the same server with no defect, so
running it first and a flaw second shows exactly what the flaw changes.

## What the baseline still reports

The baseline is not a perfect score. It draws two warnings on purpose, and
`-list` prints them with the reason each is left in: it has no
authentication, and it speaks the 2025-11-25 handshake. Every flawed server
reports those two plus the one check its flaw names, and nothing else.

## How the table stays true

The catalogue lives in [`flaws.go`](flaws.go) and nowhere else. Every CI
run starts each server, runs passmcp's engine against it with no
credentials, and fails if the findings worse than info differ in any way
from the baseline's warnings plus the flaw's own check
([`servers_test.go`](servers_test.go)).

## Limits

- The server listens on loopback by default. It is a demonstration, not a
  template: it keeps sessions in memory and implements only what the checks
  need.
- Every tool passmcp calls is read-only. `send_email` exists only for
  `toxic-pair`, is not read-only, so passmcp never calls it, and sends
  nothing if called.
