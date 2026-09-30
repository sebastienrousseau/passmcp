# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# The README demo: a real `passmcp check` against the example server with
# the toxic-pair flaw (examples/servers), on loopback. Rendered by
# `make demo`, which builds both binaries into build/demo and puts that
# directory on PATH; nothing here reaches the network.
Output .github/demo.gif
Require passmcp
Require passmcp-example-server
Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 1100
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
# The server stops itself after 90s: a hidden kill would still print a line.
Type "PS1='$ '; timeout 90 passmcp-example-server -flaw toxic-pair -addr 127.0.0.1:17801 >/dev/null 2>&1 &" Enter
# Let the set-up finish and clear it before recording starts.
Sleep 2s
Type "clear" Enter
Sleep 500ms
Show

Type "passmcp check http://127.0.0.1:17801/mcp" Sleep 400ms Enter
# The performance phase alone takes about 17s.
Sleep 22s
