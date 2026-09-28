// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
)

// currentToken extracts the cached token from a refreshing source.
func currentToken(c *passmcp.Client) *auth.Token {
	if rs, ok := c.TokenSource().(*auth.RefreshingSource); ok {
		return rs.Current()
	}
	return nil
}
