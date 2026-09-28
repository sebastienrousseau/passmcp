// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build tools

// Package passmcp's tools.go pins build-time tool dependencies in go.mod so
// scripts/gen_docs.go (which is build-ignored) resolves offline.
package passmcp

import _ "github.com/spf13/cobra/doc"
