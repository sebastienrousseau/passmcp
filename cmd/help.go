// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"satellion.com/passmcp/internal/tui"
)

// Help rendering. On a terminal the help is branded like the rest of the
// CLI family: the flame, the wordmark, a version line, then coral UPPERCASE
// sections over the reference text. Piped, cobra's plain text is kept so
// `passmcp --help | less` and documentation generators see stable output.

var (
	hHead = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(tui.Accent))
	hName = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	hText = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	hDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	hFlag = lipgloss.NewStyle().Foreground(lipgloss.Color(tui.Accent))
)

// rootExamples are the common invocations shown under EXAMPLES on the root
// help, in the two-column form draft uses.
var rootExamples = [][2]string{
	{"passmcp check URL", "test an open server"},
	{"passmcp check URL --token-env NAME", "with a bearer token"},
	{"passmcp check URL --auth client-credentials", "with OAuth"},
	{"passmcp check URL --report-dir ./out -v", "save the full report"},
	{"passmcp login URL", "sign in as a user (PKCE)"},
}

// passmcpEnv lists the environment variables, for the ENVIRONMENT section.
var passmcpEnv = []string{
	"PASSMCP_TOKEN, PASSMCP_CLIENT_ID, PASSMCP_CLIENT_SECRET, PASSMCP_BASIC,",
	"PASSMCP_CONFIG, PASSMCP_LOG_LEVEL, PASSMCP_SHOW_LOGO=0",
}

func installStyledHelp(root *cobra.Command) {
	plain := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		f, ok := out.(*os.File)
		if !ok || !isatty.IsTerminal(f.Fd()) {
			plain(cmd, args)
			return
		}
		width := 78
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 40 {
			width = min(w, 96)
		}
		renderHelp(out, cmd, width)
	})
}

func renderHelp(w io.Writer, cmd *cobra.Command, width int) {
	p := func(s string) { _, _ = fmt.Fprint(w, s) }
	head := func(s string) string { return hHead.Render(s) }
	dim := func(s string) string { return hDim.Render(s) }
	isRoot := cmd.Root() == cmd

	// logo / wordmark
	if isRoot && tui.ShowLogo() {
		p(tui.Logo(false))
	} else {
		p("\n  " + hName.Render(cmd.CommandPath()) + "\n\n")
	}
	if isRoot {
		p("  " + dim("passmcp "+Version+" — test any MCP server and see if it is ready for agents") + "\n\n")
	}

	helpIntro(p, cmd, width)

	// USAGE
	p(head("USAGE") + "\n")
	p("  " + hText.Render(cmd.UseLine()) + "\n")
	if cmd.HasAvailableSubCommands() {
		p("  " + hText.Render(cmd.CommandPath()+" <command> [flags]") + "\n")
	}
	p("\n")

	// EXAMPLES (root only)
	if isRoot {
		helpExamples(p, head, dim, width)
	}

	// COMMANDS
	if cmd.HasAvailableSubCommands() {
		helpCommands(p, head, cmd, width)
	}

	// FLAGS
	helpFlags(p, head, cmd, width)

	// ENVIRONMENT (root only)
	if isRoot {
		p(head("ENVIRONMENT") + "\n")
		for _, l := range passmcpEnv {
			p("  " + dim(l) + "\n")
		}
		p("\n")
		p(dim("  Run \""+cmd.CommandPath()+" <command> --help\" for more on a command.") + "\n")
	}
}

// helpIntro writes the command's long description, or its short one,
// wrapped to the width with paragraph breaks kept.
func helpIntro(p func(string), cmd *cobra.Command, width int) {
	// intro paragraph
	intro := strings.TrimSpace(cmd.Long)
	if intro == "" {
		intro = cmd.Short
	}
	if intro == "" {
		return
	}
	for _, line := range wrapParas(intro, width-4) {
		if line == "" {
			p("\n")
			continue
		}
		p("  " + hText.Render(line) + "\n")
	}
	p("\n")
}

// helpExamples writes the root examples, each with its comment aligned
// beside it when the line fits the width.
func helpExamples(p func(string), head, dim func(string) string, width int) {
	p(head("EXAMPLES") + "\n")
	nameW := 0
	for _, ex := range rootExamples {
		if len(ex[0]) > nameW {
			nameW = len(ex[0])
		}
	}
	for _, ex := range rootExamples {
		line := "  " + hText.Render(ex[0])
		if 2+nameW+2+len("# "+ex[1]) <= width {
			line += strings.Repeat(" ", nameW-len(ex[0])+2) + dim("# "+ex[1])
		}
		p(line + "\n")
	}
	p("\n")
}

// helpCommands writes the available subcommands in name order, their short
// descriptions wrapped under themselves.
func helpCommands(p func(string), head func(string) string, cmd *cobra.Command, width int) {
	p(head("COMMANDS") + "\n")
	cmds := append([]*cobra.Command(nil), cmd.Commands()...)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name() < cmds[j].Name() })
	nameW := 0
	for _, c := range cmds {
		if c.IsAvailableCommand() && len(c.Name()) > nameW {
			nameW = len(c.Name())
		}
	}
	for _, c := range cmds {
		if !c.IsAvailableCommand() {
			continue
		}
		lines := wrapWords(c.Short, width-nameW-6)
		p("  " + hName.Render(fmt.Sprintf("%-*s", nameW, c.Name())) + "  " + hText.Render(lines[0]) + "\n")
		for _, l := range lines[1:] {
			p("  " + strings.Repeat(" ", nameW) + "  " + hText.Render(l) + "\n")
		}
	}
	p("\n")
}

// helpFlags writes the command's own flags under FLAGS and the ones it
// inherits under GLOBAL FLAGS, each section only when it has any.
func helpFlags(p func(string), head func(string) string, cmd *cobra.Command, width int) {
	if cmd.HasAvailableLocalFlags() {
		p(head("FLAGS") + "\n")
		p(renderFlags(cmd.LocalFlags(), width))
		p("\n")
	}
	if cmd.HasAvailableInheritedFlags() {
		p(head("GLOBAL FLAGS") + "\n")
		p(renderFlags(cmd.InheritedFlags(), width))
		p("\n")
	}
}

// flagRow is one flag as the help lays it out: its name column and its
// usage text.
type flagRow struct{ name, usage string }

// maxFlagNameWidth caps the name column, so one long flag does not push
// every usage to the right; a longer name gets its usage on the lines
// below it instead.
const maxFlagNameWidth = 32

// renderFlags lays flags out as "  -s, --long type   usage", wrapping the
// usage under itself when the line is too long for the width.
func renderFlags(fs *pflag.FlagSet, width int) string {
	rows, nameW := flagRows(fs)
	var b strings.Builder
	for _, r := range rows {
		writeFlagRow(&b, r, nameW, width)
	}
	return b.String()
}

// flagRows collects the visible flags in the set's order, with the width
// of the name column: the longest name, capped at maxFlagNameWidth.
func flagRows(fs *pflag.FlagSet) ([]flagRow, int) {
	var rows []flagRow
	nameW := 0
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		r := flagRow{name: flagName(f), usage: flagUsage(f)}
		rows = append(rows, r)
		nameW = max(nameW, len(r.name))
	})
	return rows, min(nameW, maxFlagNameWidth)
}

// flagName is "-s, --long type", or "    --long type" for a flag with no
// shorthand, so long names line up either way.
func flagName(f *pflag.Flag) string {
	name := "    --" + f.Name
	if f.Shorthand != "" {
		name = "-" + f.Shorthand + ", --" + f.Name
	}
	if t, _ := pflag.UnquoteUsage(f); t != "" {
		name += " " + t
	}
	return name
}

// flagUsage is the flag's usage with its default appended, unless the
// default is a zero value not worth printing.
func flagUsage(f *pflag.Flag) string {
	switch f.DefValue {
	case "", "false", "0", "[]":
		return f.Usage
	}
	return f.Usage + fmt.Sprintf(" (default %s)", f.DefValue)
}

// writeFlagRow writes one flag. Its usage starts beside the name when the
// name fits the column, and on the next line when it does not; either way
// the rest of the usage wraps under itself.
func writeFlagRow(b *strings.Builder, r flagRow, nameW, width int) {
	lines := wrapWords(r.usage, max(20, width-nameW-6))
	if len(r.name) > nameW {
		b.WriteString("  " + hFlag.Render(r.name) + "\n")
	} else {
		b.WriteString("  " + hFlag.Render(fmt.Sprintf("%-*s", nameW, r.name)) + "  " + hDim.Render(lines[0]) + "\n")
		lines = lines[1:]
	}
	for _, l := range lines {
		b.WriteString("  " + strings.Repeat(" ", nameW) + "  " + hDim.Render(l) + "\n")
	}
}

// wrapParas reflows prose paragraphs (joining hard-wrapped lines) and folds
// each to width; blank lines and indented lines are preserved.
func wrapParas(text string, width int) []string {
	var out []string
	var para []string
	flush := func() {
		if len(para) > 0 {
			out = append(out, wrapWords(strings.Join(para, " "), width)...)
			para = nil
		}
	}
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			flush()
			out = append(out, "")
		case strings.HasPrefix(line, "  "):
			flush()
			out = append(out, strings.TrimRight(line, " "))
		default:
			para = append(para, strings.TrimSpace(line))
		}
	}
	flush()
	return out
}

// wrapWords folds text at spaces only, so flags and paths are never split.
func wrapWords(text string, width int) []string {
	if width < 10 {
		width = 10
	}
	var lines []string
	line := ""
	for _, wd := range strings.Fields(text) {
		switch {
		case line == "":
			line = wd
		case lipgloss.Width(line)+1+lipgloss.Width(wd) > width:
			lines = append(lines, line)
			line = wd
		default:
			line += " " + wd
		}
	}
	if line != "" || len(lines) == 0 {
		lines = append(lines, line)
	}
	return lines
}
