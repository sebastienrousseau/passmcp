// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// LogoEnvVar hides the logo when set to "0".
const LogoEnvVar = "PASSMCP_SHOW_LOGO"

// Accent is the coral shared across the CLI family.
const (
	Accent    = "#F56B5E"
	CoralSoft = "#FF8A7A"
)

// Wordmark and Tagline are the identity shown wherever passmcp presents
// itself, kept here so they never drift between the help and the run view.
const (
	Wordmark = "passmcp"
	Tagline  = "Test any MCP server. Trust the report."
)

// logoLines is passmcp's flame, a solid braille silhouette generated from
// .github/logo.svg so it scales with the terminal font.
var logoLines = []string{
	`    ⣠⣴⡎    `,
	`  ⢠⣾⣿⣿⣧    `,
	`⢀⣆⣾⣿⣿⣿⣿⣧  ⡀`,
	`⣾⣿⣿⣿⣿⣿⣿⣿⣧⣸⣷`,
	`⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿`,
	`⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⠇`,
	` ⠈⠛⠿⣿⣿⣿⡿⠟⠁ `,
}

// logoGradient colours the flame line by line, brightest at the tips.
var logoGradient = []string{
	"#F87171", "#FA5B4E", "#F25447", "#E14F44",
	"#D5473D", "#C93F36", "#BD362E", "#A22030", "#9F1239",
}

// ShowLogo reports whether the logo may be drawn (PASSMCP_SHOW_LOGO != "0").
func ShowLogo() bool { return os.Getenv(LogoEnvVar) != "0" }

// Logo returns the gradient flame with the wordmark and tagline. When
// compact, the tagline sits beside the wordmark and the surrounding blank
// lines are dropped, so the block still fits a standard 24-row terminal.
func Logo(compact bool) string {
	var sb strings.Builder
	if !compact {
		sb.WriteString("\n")
	}
	for i, line := range logoLines {
		c := logoGradient[i%len(logoGradient)]
		sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(line) + "\n")
	}
	sb.WriteString("\n")
	accent := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(Accent))
	if compact {
		sb.WriteString("  " + accent.Render(Wordmark) + "  " + lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(Tagline) + "\n")
		return sb.String()
	}
	sb.WriteString("  " + accent.Render(Wordmark) + "\n")
	sb.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(Tagline) + "\n\n")
	return sb.String()
}

// GetStyledLogo returns the full (non-compact) logo, for the selector.
func GetStyledLogo() string { return Logo(false) }
