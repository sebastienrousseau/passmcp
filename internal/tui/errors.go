// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import "satellion.com/passmcp/internal/termsafe"

// shownError is a listing error as the selector draws it. Its text often
// quotes the server, so it is cleaned of terminal control sequences; the
// error it wraps is still there for errors.Is and errors.As.
type shownError struct{ err error }

func (e shownError) Error() string { return termsafe.String(e.err.Error()) }
func (e shownError) Unwrap() error { return e.err }
