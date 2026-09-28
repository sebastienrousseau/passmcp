---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp's config file, profiles and environment variables. Every flag is a setting, so there is no second schema to learn.
---

# Configuration

## The config file

`~/.config/passmcp/config.json`, or `$XDG_CONFIG_HOME/passmcp/config.json`,
or wherever `PASSMCP_CONFIG` or `--config` points. Keys are flag names, so
the file has no schema of its own and every flag is a setting.

```json
{
  "defaults": { "rps": 4, "report-dir": "./passmcp-reports" },
  "profiles": {
    "prod": {
      "endpoint": "https://mcp.example.com/mcp",
      "settings": {
        "auth": "client-credentials",
        "client-id": "acme",
        "client-secret-env": "ACME_SECRET",
        "param": ["profile_id=tenant-1"],
        "deny": ["send_email"]
      }
    }
  }
}
```

```bash
passmcp check --profile prod
```

A profile supplies the endpoint and its settings; a positional endpoint
on the command line still wins. Keep secrets in the environment and
reference them with the `*-env` settings.

## Precedence

Highest first: an explicit flag, the selected profile, the `defaults`
block, the flag's built-in default. Environment variables are a separate
layer for secrets only (`PASSMCP_TOKEN`, `PASSMCP_CLIENT_ID`,
`PASSMCP_CLIENT_SECRET`, `PASSMCP_BASIC`), consulted when the matching flag
is unset.

A setting that names no flag anywhere in the CLI is an error, not a
silent no-op: a typo that is quietly ignored is worse than one that
fails, because you believe it took effect.

## The commands

```bash
passmcp config init       # write a commented template listing every setting
passmcp config validate   # parse the file and reject unknown settings
passmcp config show       # print the effective file as JSON
```

The template's lines are valid JSON once uncommented. Lines that are only
a `//` comment are stripped when the file is loaded.

## Settings reference

Every flag of `passmcp check` is a setting. The ones people set in a file:

| Setting | Default | Meaning |
|---|---|---|
| `auth` | `auto` | credential mode |
| `token-env`, `client-id`, `client-secret-env`, `scope`, `param`, `header` | | credentials, see [Credentials](credentials.md) |
| `allow-mutations`, `allow-destructive`, `only`, `deny`, `arg` | | execution policy |
| `samples` | 5 | repeat calls per tool in the performance phase |
| `concurrency` | 4 | workers in the burst; 0 disables |
| `rps` | 2 | requests per second; 0 disables throttling |
| `timeout` | `30s` | per call |
| `seed` | 1 | for generated arguments |
| `fill-optional` | false | also generate optional schema properties |
| `allow-load` | false | run the burst unthrottled |
| `max-resources`, `max-prompts` | 25 | caps for reads and renders |
| `soak` | 0 | extra calls of one tool after the run, with the server's resident memory sampled after each; stdio only, at least 100 |
| `output` | `text` | `text`, `json`, `md`, `ndjson` |
| `report-dir` | | write every format plus telemetry here |
| `capture-bodies`, `events`, `verbose`, `no-color` | false | output detail |
| `phases`, `skip-phases` | | select phases |

## The token store

`passmcp login` writes `~/.config/passmcp/tokens.json` (mode 0600, one entry
per endpoint) holding the access and refresh tokens, the token endpoint,
the client id and secret used, the resource and issuer. `passmcp check
--auth authorization-code` and `passmcp call` read it and refresh through
it. Delete the entry to log out.
