<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Software Bill of Materials (SBOM)

**Project:** passmcp
**Format:** Go Modules (`go.mod` / `go.sum`)

passmcp is a compiled Go application. The canonical source of truth for all
runtime dependencies, version constraints, and cryptographic checksums is
the `go.mod` and `go.sum` files located at the root of the repository.

## Core Dependencies

Versions pinned in `go.mod`. Refresh this table whenever a direct dependency
is bumped.

| Component | Version | Purpose | License |
|:----------|:--------|:--------|:--------|
| `github.com/mattn/go-isatty` | v0.0.24 | Terminal detection, to decide whether the text report is coloured | MIT |
| `github.com/spf13/cobra` | v1.10.2 | CLI framework; also renders the generated manpages and completions | Apache-2.0 |
| `github.com/charmbracelet/bubbletea` | v1.3.10 | Terminal UI runtime: the progress view during a run and the interactive tool selector | MIT |
| `github.com/charmbracelet/bubbles` | v1.0.0 | Progress bar, spinner and table components used by the TUI | MIT |
| `github.com/charmbracelet/lipgloss` | v1.1.0 | Terminal styling for the TUI, the logo and the text report | MIT |
| `github.com/charmbracelet/x/term` | v0.2.2 | Terminal width, to fit `check` output and the help screen to the window | MIT |
| `github.com/muesli/termenv` | v0.16.0 | Colour profile selection when the text report is written to a terminal | MIT |
| `github.com/spf13/pflag` | v1.0.10 | CLI flag parsing; the shared flag groups and the flag-keyed config file | BSD-3-Clause |
| `satellion.com/passmcp-reporting` | v0.0.5 | The attestation format's statement types and offline verifier, the A2A predicate and the graph model, first-party, split out so gateways can import it without this module's graph; standard library only | Apache-2.0 |
| `golang.org/x/sys` | v0.48.0 | Windows only: reads and sets the token store's access-control list (`internal/creds`), which Go's standard library cannot; already compiled into the Windows binary through the terminal libraries, now imported directly | BSD-3-Clause |
| `go.yaml.in/yaml/v3` | v3.0.5 | Parses fleet files (`passmcp fleet run fleet.yaml`); already in the build through cobra, now imported directly rather than adding a second YAML parser | MIT and Apache-2.0 |

This table lists every **direct** requirement in `go.mod`, and
`make sbom-check` (run in CI's Repository Checks, and by `make sbom`) fails
if its components or versions drift from that file in either direction. Indirect
dependencies (`mousetrap`, `golang.org/x/text`) are not enumerated here:
`go.sum` is the authoritative, checksummed record, and a hand-maintained
copy of it would be wrong within a week.

Everything passmcp does on the wire — HTTP with `httptrace` timings, TLS,
JSON-RPC, Server-Sent Events, OAuth 2.1 with PKCE, RFC 9728 and RFC 8414
discovery, RFC 7591 registration, HAR export — is implemented on the Go
standard library. There is no HTTP client, OAuth or MCP SDK dependency, so
the behaviour passmcp reports on is the behaviour of a client it fully
controls.

## System Dependencies

None required. passmcp is a single static binary and never invokes a
shell. It runs another program only when asked to: the server command
given after `--stdio --`, the platform's keyring helper (`security` on
macOS, `secret-tool` on Linux) when tokens are kept in the keyring, and
the platform's URL opener (`open`, `xdg-open` or `rundll32`) when
`passmcp serve` opens a browser.

## Development & Build Dependencies

| Component | Type | Version Constraint | License |
|:----------|:-----|:-------------------|:--------|
| Go | Compiler/Toolchain | as pinned by the `go` directive in `go.mod` | BSD-3-Clause |
| GoReleaser | Release Automation | v2+ | MIT |
| GNU Make | Build tool | Any | GPL-3.0 |
| golangci-lint | Linter (`make lint`) | pinned in `.github/workflows/ci.yml` | GPL-3.0 |

## Supply Chain Notes

- All third-party code is managed via Go modules with cryptographic
  checksums recorded in `go.sum`.
- `CGO_ENABLED=0` everywhere; released binaries are static.
- Binaries are compiled natively via GitHub Actions and GoReleaser, signed
  keylessly with cosign, and attested with SLSA build provenance.
- All commits are cryptographically signed and carry a DCO trailer.
