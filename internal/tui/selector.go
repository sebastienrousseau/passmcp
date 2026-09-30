// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"satellion.com/passmcp/internal/termsafe"
)

// Item is one tool offered in the selector.
type Item struct {
	Name string
	// Kind is read-only, mutating or destructive (the policy classes).
	Kind string
	// Policy is "allowed" when the default policy would run it, or "opt-in".
	Policy      string
	Description string
}

// FetchFunc lists the tools the selector offers.
type FetchFunc func() ([]Item, error)

type selectorModel struct {
	items      []Item
	filtered   []Item
	filter     string
	selected   map[string]bool
	table      table.Model
	spinner    spinner.Model
	loading    bool
	loadingErr error
	confirmed  bool
	quitting   bool
	fetchFn    FetchFunc

	showHelp bool
	cmdErr   string
}

var runSelectorProgram = func(ctx context.Context, model tea.Model) (tea.Model, error) {
	return tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx)).Run()
}

// NewSelectorModel creates the Bubble Tea model for the tool selector.
func NewSelectorModel(fetchFn FetchFunc) *selectorModel {
	columns := []table.Column{
		{Title: " ", Width: 3},
		{Title: "Tool", Width: 35},
		{Title: "Kind", Width: 15},
		{Title: "Policy", Width: 10},
	}
	t := table.New(table.WithColumns(columns), table.WithFocused(true), table.WithHeight(12))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("255")).Background(lipgloss.Color(Accent)).Bold(true)
	t.SetStyles(s)

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(Accent))

	return &selectorModel{fetchFn: fetchFn, loading: true, selected: map[string]bool{}, table: t, spinner: sp}
}

type fetchedItemsMsg struct {
	items []Item
	err   error
}

// Init starts the spinner and the fetch of the tool list.
func (m *selectorModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		items, err := m.fetchFn()
		return fetchedItemsMsg{items: items, err: err}
	})
}

func (m *selectorModel) applyFilter() {
	if strings.HasPrefix(m.filter, "/") {
		return
	}
	var filtered []Item
	for _, it := range m.items {
		nameMatch := strings.Contains(strings.ToLower(it.Name), strings.ToLower(m.filter))
		kindMatch := strings.Contains(strings.ToLower(it.Kind), strings.ToLower(m.filter))
		if m.filter == "" || nameMatch || kindMatch {
			filtered = append(filtered, it)
		}
	}
	m.filtered = filtered
	m.updateTableRows()
}

func (m *selectorModel) updateTableRows() {
	rows := make([]table.Row, 0, len(m.filtered))
	for range m.filtered {
		rows = append(rows, table.Row{"", "", "", ""})
	}
	m.table.SetRows(rows)
}

func (m *selectorModel) renderCustomTable() string {
	var sb strings.Builder
	headerRow := fmt.Sprintf("%s  %-35s  %-15s  %-10s", "   ", "Tool", "Kind", "Policy")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252")).Render(headerRow) + "\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("─"+strings.Repeat("─", 69)) + "\n")

	cursor := m.table.Cursor()
	start := 0
	if cursor >= 10 {
		start = cursor - 9
	}
	end := start + 12
	if end > len(m.filtered) {
		end = len(m.filtered)
	}
	for i := start; i < end; i++ {
		it := m.filtered[i]
		checkChar := "·"
		if m.selected[it.Name] {
			checkChar = "✔"
		}
		// The name is the server's; the selection stays keyed by it, and
		// only what is drawn is cleaned.
		name := termsafe.String(it.Name)
		if len(name) > 35 {
			name = name[:32] + "..."
		}
		if i == cursor {
			rowContent := fmt.Sprintf("%s    %-35s  %-15s  %-10s", checkChar, name, it.Kind, it.Policy)
			sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Background(lipgloss.Color(Accent)).Bold(true).Render(rowContent) + "\n")
			continue
		}
		styledCheck := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(checkChar)
		if m.selected[it.Name] {
			styledCheck = lipgloss.NewStyle().Foreground(lipgloss.Color(Accent)).Render(checkChar)
		}
		nameStr := lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Render(fmt.Sprintf("%-35s", name))
		kindStr := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(fmt.Sprintf("%-15s", it.Kind))
		polStr := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(fmt.Sprintf("%-10s", it.Policy))
		_, _ = fmt.Fprintf(&sb, "%s    %s  %s  %s\n", styledCheck, nameStr, kindStr, polStr)
	}
	for i := end - start; i < 12; i++ {
		sb.WriteString("\n")
	}
	return sb.String()
}

// slashCommands are the in-session commands the filter line accepts.
var slashCommands = []string{"/exit", "/quit", "/help", "/all", "/none", "/sort"}

// Update handles one Bubble Tea message; keys the selector does not
// consume go to the embedded table, which owns cursor movement.
func (m *selectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case fetchedItemsMsg:
		return m.handleFetched(msg)
	case tea.KeyMsg:
		m.cmdErr = ""
		if model, keyCmd, handled := m.handleKey(msg); handled {
			return model, keyCmd
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// handleFetched installs the tool list, selecting by default every tool
// the safety policy would run anyway.
// shownError is a listing error as the selector draws it. Its text often
// quotes the server, so it is cleaned of terminal control sequences; the
// error it wraps is still there for errors.Is and errors.As.
type shownError struct{ err error }

func (e shownError) Error() string { return termsafe.String(e.err.Error()) }
func (e shownError) Unwrap() error { return e.err }

func (m *selectorModel) handleFetched(msg fetchedItemsMsg) (tea.Model, tea.Cmd) {
	m.loading = false
	if msg.err != nil {
		m.loadingErr = shownError{msg.err}
		return m, tea.Quit
	}
	m.items = msg.items
	m.filtered = msg.items
	for _, it := range msg.items {
		m.selected[it.Name] = it.Policy == "allowed"
	}
	m.updateTableRows()
	return m, nil
}

func (m *selectorModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	switch msg.String() {
	case "ctrl+c", "esc", "?":
		return m.handleControl(msg.String())
	case "right", "tab":
		if completed, ok := completeSlashCommand(m.filter); ok {
			m.filter = completed
			return m, nil, true
		}
	case "enter":
		return m.handleEnter()
	case " ", "space":
		return m.handleSpace()
	case "backspace":
		return m.handleBackspace()
	case "ctrl+a":
		return m.setFilteredSelection(true)
	case "ctrl+n":
		return m.setFilteredSelection(false)
	default:
		return m.handleTyped(msg)
	}
	return m, nil, false
}

// handleControl handles quitting and the help overlay: ctrl+c quits, esc
// closes the help or quits, and ? toggles the help once the list loaded.
func (m *selectorModel) handleControl(key string) (tea.Model, tea.Cmd, bool) {
	switch key {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit, true
	case "esc":
		if m.showHelp {
			m.showHelp = false
			return m, nil, true
		}
		m.quitting = true
		return m, tea.Quit, true
	case "?":
		if !m.loading {
			m.showHelp = !m.showHelp
			return m, nil, true
		}
	}
	return m, nil, false
}

// handleBackspace deletes the last filter character; while loading it
// swallows the key.
func (m *selectorModel) handleBackspace() (tea.Model, tea.Cmd, bool) {
	if m.loading {
		return m, nil, true
	}
	if len(m.filter) > 0 {
		m.filter = m.filter[:len(m.filter)-1]
		m.applyFilter()
	}
	return m, nil, true
}

// handleTyped appends a printable ASCII key to the filter; any other key
// goes on to the table, except while loading, when it is swallowed.
func (m *selectorModel) handleTyped(msg tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	if m.loading {
		return m, nil, true
	}
	if len(msg.String()) == 1 && len(msg.Runes) > 0 && msg.Runes[0] >= 32 && msg.Runes[0] <= 126 {
		m.filter += msg.String()
		m.applyFilter()
		return m, nil, true
	}
	return m, nil, false
}

func (m *selectorModel) handleEnter() (tea.Model, tea.Cmd, bool) {
	if m.loading {
		return m, nil, true
	}
	if strings.HasPrefix(m.filter, "/") {
		target := m.filter
		for _, cmd := range slashCommands {
			if strings.HasPrefix(cmd, m.filter) {
				target = cmd
				break
			}
		}
		cmd := m.executeSlashCommand(target)
		m.filter = ""
		return m, cmd, true
	}
	m.confirmed = true
	return m, tea.Quit, true
}

func (m *selectorModel) handleSpace() (tea.Model, tea.Cmd, bool) {
	if m.loading {
		return m, nil, true
	}
	if strings.HasPrefix(m.filter, "/") {
		m.filter += " "
		return m, nil, true
	}
	if len(m.filtered) > 0 {
		idx := m.table.Cursor()
		if idx >= 0 && idx < len(m.filtered) {
			name := m.filtered[idx].Name
			m.selected[name] = !m.selected[name]
			m.updateTableRows()
		}
	}
	return m, nil, true
}

func (m *selectorModel) setFilteredSelection(selected bool) (tea.Model, tea.Cmd, bool) {
	if m.loading {
		return m, nil, true
	}
	for _, it := range m.filtered {
		m.selected[it.Name] = selected
	}
	m.updateTableRows()
	return m, nil, true
}

func completeSlashCommand(filter string) (string, bool) {
	if !strings.HasPrefix(filter, "/") {
		return "", false
	}
	for _, cmd := range slashCommands {
		if len(cmd) > len(filter) && strings.HasPrefix(cmd, filter) {
			return cmd, true
		}
	}
	return "", false
}

// View renders the logo, the search or command prompt, the tool table or
// the help panel, the shortcut bar and the footer.
func (m *selectorModel) View() string {
	var header string
	if ShowLogo() {
		header = GetStyledLogo()
	} else {
		header = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Render("passmcp - Select Tools") + "\n\n"
	}
	out := header
	if m.loading {
		out += fmt.Sprintf("   %s Connecting and listing tools...\n\n", m.spinner.View())
		out += lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("   [esc] cancel") + "\n"
		return out
	}
	if m.loadingErr != nil {
		out += fmt.Sprintf("   %s\n\n", lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("Error: "+m.loadingErr.Error()))
		out += lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("   [esc] exit") + "\n"
		return out
	}
	var promptStr string
	if strings.HasPrefix(m.filter, "/") {
		labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
		cmdStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(Accent))
		suggStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		var suggestion string
		for _, cmd := range slashCommands {
			if len(cmd) > len(m.filter) && strings.HasPrefix(cmd, m.filter) {
				suggestion = cmd[len(m.filter):]
				break
			}
		}
		promptStr = labelStyle.Render("  Command: ") + cmdStyle.Render(m.filter) + labelStyle.Render("_") + suggStyle.Render(suggestion)
	} else {
		promptStr = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("  Search tools (%d found): %s_", len(m.filtered), m.filter))
	}
	out += promptStr + "\n"
	out += lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("  "+strings.Repeat("─", 58)) + "\n\n"
	if m.cmdErr != "" {
		out += "  " + lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(m.cmdErr) + "\n\n"
	}
	if m.showHelp {
		out += m.renderHelpPanel() + "\n"
	} else {
		for _, line := range strings.Split(m.renderCustomTable(), "\n") {
			out += "  " + line + "\n"
		}
		out += "\n"
	}
	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(Accent)).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("239"))
	out += fmt.Sprintf("  %s %s %s  %s %s %s  %s %s %s  %s %s %s  %s %s\n",
		keyStyle.Render("[space]"), descStyle.Render("toggle"), sepStyle.Render("•"),
		keyStyle.Render("[ctrl+a]"), descStyle.Render("all"), sepStyle.Render("•"),
		keyStyle.Render("[ctrl+n]"), descStyle.Render("none"), sepStyle.Render("•"),
		keyStyle.Render("[/]"), descStyle.Render("command"), sepStyle.Render("•"),
		keyStyle.Render("[enter]"), descStyle.Render("run"))
	out += "\n" + m.renderFooter()
	return out
}

// RunSelector launches the interactive selector and returns the chosen
// tools, whether the user confirmed, and any error.
func RunSelector(ctx context.Context, fetchFn FetchFunc) ([]Item, bool, error) {
	m, err := runSelectorProgram(ctx, NewSelectorModel(fetchFn))
	if err != nil {
		return nil, false, err
	}
	selModel := m.(*selectorModel)
	if selModel.loadingErr != nil {
		return nil, false, selModel.loadingErr
	}
	if selModel.quitting || !selModel.confirmed {
		return nil, false, nil
	}
	var out []Item
	for _, it := range selModel.items {
		if selModel.selected[it.Name] {
			out = append(out, it)
		}
	}
	return out, true, nil
}

func (m *selectorModel) executeSlashCommand(cmdStr string) tea.Cmd {
	m.cmdErr = ""
	parts := strings.Fields(strings.TrimSpace(cmdStr))
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "/exit", "/quit":
		m.quitting = true
		m.confirmed = false
		return tea.Quit
	case "/help":
		m.showHelp = true
	case "/all":
		for _, it := range m.filtered {
			m.selected[it.Name] = true
		}
		m.updateTableRows()
	case "/none":
		for _, it := range m.filtered {
			m.selected[it.Name] = false
		}
		m.updateTableRows()
	case "/sort":
		if len(parts) < 2 {
			m.cmdErr = "Usage: /sort <name|kind|policy|read-only|mutating|destructive>"
			return nil
		}
		field := strings.ToLower(parts[1])
		switch field {
		case "name":
			sort.SliceStable(m.filtered, func(i, j int) bool { return strings.ToLower(m.filtered[i].Name) < strings.ToLower(m.filtered[j].Name) })
		case "kind":
			sort.SliceStable(m.filtered, func(i, j int) bool { return m.filtered[i].Kind < m.filtered[j].Kind })
		case "policy":
			sort.SliceStable(m.filtered, func(i, j int) bool { return m.filtered[i].Policy < m.filtered[j].Policy })
		case "read-only", "readonly", "mutating", "destructive":
			want := strings.ReplaceAll(field, "readonly", "read-only")
			sort.SliceStable(m.filtered, func(i, j int) bool {
				iK, jK := m.filtered[i].Kind == want, m.filtered[j].Kind == want
				if iK != jK {
					return iK
				}
				return strings.ToLower(m.filtered[i].Name) < strings.ToLower(m.filtered[j].Name)
			})
		default:
			m.cmdErr = fmt.Sprintf("Unknown sort field: %s (choose name, kind, policy, read-only, mutating or destructive)", parts[1])
		}
		m.updateTableRows()
	default:
		m.cmdErr = fmt.Sprintf("Unknown command: %s. Type /help for help.", parts[0])
	}
	return nil
}

func (m *selectorModel) renderHelpPanel() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(Accent)).Render("   In-Session Commands") + "\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("   "+strings.Repeat("─", 58)) + "\n\n")
	commands := [][]string{
		{"/sort <field>", "Sort list by name, kind, policy, or a kind first (read-only, mutating, destructive)"},
		{"/all", "Select all filtered tools"},
		{"/none", "Deselect all filtered tools"},
		{"/exit, /quit", "Exit without running"},
		{"/help", "Show this command help menu"},
	}
	for _, c := range commands {
		sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(Accent)).Render(fmt.Sprintf("   %-16s", c[0])))
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(c[1]) + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("   Press [?] or [esc] to return to the tool list.") + "\n")
	for i := len(commands) + 5; i < 15; i++ {
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m *selectorModel) renderFooter() string {
	vStr := Version
	if vStr == "" {
		vStr = "dev"
	}
	left := " ? for commands"
	right := fmt.Sprintf("Made with ❤️ in London, UK (v%s)", vStr)
	spacesCount := 71 - len(left) - len([]rune(right)) + 1
	if spacesCount < 1 {
		spacesCount = 2
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(fmt.Sprintf(" %s%s%s", left, strings.Repeat(" ", spacesCount), right)) + "\n"
}
