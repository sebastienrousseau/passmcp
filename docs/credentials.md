---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Bearer tokens, OAuth, HTTP basic, API-key headers: how to hand passmcp the credential you were given without it ever leaving your machine.
---

# Credentials

Whatever you were handed, there is a flag for it, usually an environment
variable, and a config-profile setting with the same name as the flag.

## By what you were given

| You were given | Use |
|---|---|
| a bearer token | `--token`, `--token-env NAME`, or `PASSMCP_TOKEN` |
| an API key or tenant header | `--header "X-API-Key: …"` (repeatable; `Name=value` also accepted) |
| a username and password | `--basic user:pass` or `PASSMCP_BASIC` |
| an OAuth client id and secret | `--auth client-credentials --client-id … --client-secret-env NAME` (or `PASSMCP_CLIENT_ID`, `PASSMCP_CLIENT_SECRET`) |
| extra token parameters (tenant, profile, audience) | `--param key=value` (repeatable) |
| a scope | `--scope "a b"` (default: what the server's challenge asks for, then the PRM's `scopes_supported`) |
| a token endpoint but no discovery | `--token-url … [--auth-url …] [--resource …]` |
| a hosted Client ID Metadata Document | `--client-metadata-url https://…` |
| a user login | `passmcp login <endpoint>`, then `--auth authorization-code` |

## Modes

`--auth` selects the mode; the default `auto` picks from what is set.

| Mode | Behaviour |
|---|---|
| `none` | sends no credentials; a 401 is a critical failure |
| `bearer` | sends the pre-issued token on every request; no discovery is needed, though it is still attempted and reported |
| `client-credentials` | on a 401, discovers the authorization server, obtains a client identity, runs the client-credentials grant with the RFC 8707 `resource` indicator, and uses the token |
| `authorization-code` | uses the token `passmcp login` stored for this endpoint, refreshing it if it has expired |

Headers and basic auth are sent in every mode, on every request, including
the ones to the authorization server.

## Client identity

For `client-credentials`, the identity is chosen in this order:

1. a Client ID Metadata Document, when the server advertises support and
   `--client-metadata-url` is set;
2. the `--client-id` (and secret) you supplied;
3. RFC 7591 dynamic registration, when the server offers a registration
   endpoint.

An explicit client id always wins over registering anew: an operator who
was handed one chose it deliberately.

## Precedence and sources

An explicit flag wins, then the selected profile, then the config file's
defaults, then the environment for secrets. The report records where each
credential came from (`flag --token`, `env MCP_TOKEN`, `profile prod`),
never its value.

## The token store

`passmcp login` runs the OAuth 2.1 authorization-code flow with PKCE
(S256): it discovers the authorization server, registers or uses the
supplied client id, prints the consent URL, receives the redirect on
`http://127.0.0.1:<--redirect-port>/callback` (default 8976), redeems the
code, and saves the tokens to `$XDG_CONFIG_HOME/passmcp/tokens.json`
(`~/.config/passmcp/tokens.json`) with mode 0600, keyed by endpoint. Later
runs with `--auth authorization-code` load and refresh it.

## What is redacted

Operator-supplied secrets are registered with the redactor before the
first request. Beyond that, `Authorization`, cookies and any header whose
name contains key, token or secret are masked by name; `code`, `state`,
`client_secret`, `refresh_token` and friends are masked in URLs and form
bodies; and `access_token`, `refresh_token`, `client_secret`, `id_token`
and similar keys are masked inside JSON bodies, with their values
registered so a token issued mid-run is masked wherever it appears
afterwards. Content types are not trusted: a body that starts with `{`
is treated as JSON.
