---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Diagnose an MCP server that runs as a program rather than a URL: what passmcp starts, which checks apply over a pipe, which cannot, and what it hands the child process.
---

# Servers that are programs

Most MCP servers are not endpoints. They are programs a host starts, talks
to over a pipe, and is responsible for stopping. Point passmcp at one with
`--stdio` and the command after `--`:

```bash
passmcp check --stdio -- npx -y @modelcontextprotocol/server-everything stdio
passmcp check --stdio -- uvx mcp-server-git --repository .
passmcp check --stdio --stdio-env GITHUB_TOKEN -- docker run -i --rm ghcr.io/example/mcp
```

passmcp starts the process, runs the same phases against it, and stops it
again — politely first, by closing its stdin, then by force if it ignores
that. The process is reaped on every path out, including a cancelled run
and a panic in a phase. A diagnostic that leaves a server running has done
damage no report undoes.

Everything after `--` belongs to the server. That is what lets a server
have its own flags without passmcp guessing whose they are, and it is also
why there is no `--stdio-command "npx -y thing"` form: splitting a command
string means quoting rules, and quoting rules mean a shell. There is no
shell here. The command is executed as named, with the arguments as given.

`check`, `connect`, `tools` and `call` all take `--stdio`. For `call`, which
has two operands, the tool comes before `--` and the server after it:

```bash
passmcp call --stdio get-sum --arg a=2 --arg b=3 -- npx -y @modelcontextprotocol/server-everything stdio
```

## What the server is handed

A stdio server is a program nobody has audited, running with your user's
privileges, on the machine where your credentials live. So it is given a
fixed base environment and nothing else:

```text
PATH HOME TMPDIR TEMP TMP LANG LC_ALL SystemRoot COMSPEC PATHEXT
```

That is enough for a program to find its interpreter and its libraries. It
does not include your cloud credentials, your tokens for three other
services, or the CI secrets that happen to be exported in the shell you
typed the command into. This is a deliberate departure from how `exec`
works everywhere else, where a child inherits everything.

A server that legitimately needs a credential is given it by name:

| Flag | Effect |
|---|---|
| `--stdio-env NAME` | forward `NAME` from your environment (repeatable) |
| `--stdio-set NAME=value` | set the child's environment to exactly this (repeatable, replaces the base) |
| `--stdio-dir PATH` | run the server in this working directory |

Every run reports what it passed, as `stdio.environment`, because a server
that behaves differently under passmcp than in your own shell almost always
differs here.

## Credentials

There are none. A pipe carries no bearer token, there is no origin to
authorize against, and no authorization server to discover. `--token`,
`--auth client-credentials` and the rest are refused rather than ignored:
silently dropping a credential you passed would produce a report that looks
like a test of an authenticated server and is not.

What a stdio server needs instead goes in its arguments or in its
environment, which is why `--stdio-env` exists.

## Which checks apply

Seven of the nine phases run unchanged: the handshake, the protocol probes
that are about JSON-RPC, the catalog, execution, performance. Two have no
subject over a pipe and are reported as skipped, with the reason:

| Phase | Why it is skipped |
|---|---|
| `discovery` | a child process has no origin and no metadata to discover; the trust decision was made when you chose which program to run |
| `auth` | there is nothing to authenticate to, so there is also no wrong credential to send and no refusal to check |

Seven conformance probes inside the protocol phase are about the HTTP
binding rather than about MCP, and are likewise skipped by name:
`protocol.accept_header`, `protocol.get_stream`,
`protocol.bogus_session`, `protocol.version_header`, `protocol.origin`,
`protocol.notification_ack` and `protocol.content_type` — a pipe has no
headers to send or label, no listener to rebind and no status to
acknowledge with. So is
`handshake.session`: over a pipe the connection *is* the session, so there
is no session id a correct server would issue.

None of these is left out of the report. A run that silently contained
fewer checks would read as a better result than it is.

## Which checks only exist here

Five checks have no HTTP equivalent, and they are the ones that catch the
failures specific to this transport.

| Check | What it looks for |
|---|---|
| `stdio.process` | the program started and is still running before the first request |
| `stdio.environment` | what passmcp handed the child, as a statement rather than a judgement |
| `stdio.alive` | it was still running when the run finished |
| `stdio.stdout_clean` | nothing but JSON-RPC messages on stdout |
| `stdio.stderr` | what it logged, kept and reported |

`stdio.stdout_clean` is the one that earns its place. Over stdio, stdout is
the wire: every byte on it is parsed as protocol framing. One startup
banner, one `print` left in a handler, one progress bar, and the stream is
corrupt — and what a host reports is a hang, or a parse error naming a line
nobody wrote. It never names the cause. passmcp does, and quotes the line.

Logging to stderr, by contrast, is correct behaviour. passmcp keeps it,
reports it as `stdio.stderr`, and puts it in the evidence of any finding
about a server that died, because a stdio server that fails says why there
and nowhere else.

## Detecting the protocol generation

Over HTTP, passmcp tells the two generations of the protocol apart using a
status code: the 2026-07-28 revision answers an unimplemented RPC with 404
carrying `-32601`, while a handshake-era server answers the same `-32601`
at 200. A pipe has no status code, so that distinction is not available.

What passmcp does instead is narrower and it says so: a server that answers
`server/discover` speaks the stateless revision; anything else is treated
as handshake-era and the handshake that follows settles it. The one case
this cannot name is a stateless server that omits the optional
`server/discover`, and the finding's reason says exactly that rather than
guessing.

## Timeouts do not kill the server

A call that times out is a finding about that call. Over a pipe it would be
easy to make it fatal — the read is blocked on a descriptor only the
process can release — and the first version of the transport did exactly
that. It meant one slow tool ended the whole run, while the same timeout
over HTTP costs a single finding. It does not any more: the connection has
one reader that matches replies to requests by id, so an abandoned call is
abandoned and the next one is unaffected. The late reply is discarded
rather than handed to whoever asked next.

That reader is also what lets the performance phase mean anything here: the
parallel burst runs in parallel, instead of queueing behind one lock and
measuring passmcp.

## The browser will not do this

`passmcp serve` refuses a run that names a program, and says so, unless it
was started with `--allow-stdio`. The engine can do it and the CLI does,
but "diagnose the URL in this field" and "run this command on the machine
passmcp is running on" are not the same permission — and the token in the
page's URL is not a credential anybody should be able to trade for the
second. In `--public` mode it is refused whatever the flags say.
