// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

func TestLogo(t *testing.T) {
	if len(logoLines) == 0 || len(logoGradient) == 0 {
		t.Fatal("logo and gradient must be non-empty")
	}
	full := Logo(false)
	if !strings.Contains(full, Wordmark) || !strings.Contains(full, Tagline) || !strings.Contains(full, "⣿") {
		t.Errorf("full logo = %q", full)
	}
	compact := Logo(true)
	if strings.Count(compact, "\n") >= strings.Count(full, "\n") {
		t.Error("compact logo should be shorter")
	}
	if !strings.Contains(compact, Wordmark) || !strings.Contains(compact, Tagline) {
		t.Errorf("compact logo = %q", compact)
	}
	if GetStyledLogo() != full {
		t.Error("GetStyledLogo is the full logo")
	}
	t.Setenv(LogoEnvVar, "0")
	if ShowLogo() {
		t.Error("PASSMCP_SHOW_LOGO=0 must disable the logo")
	}
	t.Setenv(LogoEnvVar, "1")
	if !ShowLogo() {
		t.Error("logo enabled by default")
	}
}

func TestRunModel(t *testing.T) {
	m := NewRunModel("http://x/mcp", "no credentials", []Phase{{"net", "Connectivity"}, {"auth", "Credentials"}, {"catalog", "Catalog"}})
	_ = m.Init()
	next, _ := m.Update(tea.WindowSizeMsg{Width: 90, Height: 30})
	m = next.(*RunModel)
	v := m.View()
	for _, want := range []string{"passmcp", "http://x/mcp", "no credentials", "Connectivity", "3 phases", "q"} {
		if !strings.Contains(v, want) {
			t.Errorf("initial view lacks %q:\n%s", want, v)
		}
	}
	next, _ = m.Update(PhaseStartMsg{Name: "net"})
	m = next.(*RunModel)
	next, _ = m.Update(spinner.TickMsg{})
	m = next.(*RunModel)
	if m.steps[0].status != "running" || !strings.Contains(m.View(), "checking") {
		t.Errorf("running step: %+v", m.steps[0])
	}
	next, _ = m.Update(PhaseDoneMsg{Name: "net", Action: "PASS", Duration: 1500 * time.Millisecond, Message: "reachable over TLS"})
	m = next.(*RunModel)
	next, _ = m.Update(PhaseDoneMsg{Name: "auth", Action: "WARN", Message: "1 thing to improve"})
	m = next.(*RunModel)
	next, _ = m.Update(PhaseDoneMsg{Name: "catalog", Action: "SKIP", Message: "not needed"})
	m = next.(*RunModel)
	v = m.View()
	for _, want := range []string{"✓", "reachable over TLS", "1.5s", "△", "1 thing to improve", "–"} {
		if !strings.Contains(v, want) {
			t.Errorf("progress view lacks %q:\n%s", want, v)
		}
	}
	// DoneMsg quits without aborting
	next, cmd := m.Update(DoneMsg{})
	m = next.(*RunModel)
	if cmd == nil || !m.done || m.Aborted() {
		t.Error("DoneMsg must quit and not abort")
	}
	// quitting mid-run cancels and aborts
	cancelled := false
	m2 := NewRunModel("e", "none", []Phase{{"net", "Net"}})
	m2.Cancel = func() { cancelled = true }
	next, cmd = m2.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil || !next.(*RunModel).Aborted() || !cancelled {
		t.Error("ctrl+c mid-run must cancel and abort")
	}
	if !strings.Contains(next.(*RunModel).View(), "Stopped.") {
		t.Error("aborted view shows Stopped.")
	}
	if ResultIcon("PASS") != "✓" || ResultIcon("FAIL") != "✕" || ResultIcon("SKIP") != "–" || ResultIcon("WARN") != "△" {
		t.Error("icons")
	}
	if fmtDuration(2*time.Second) != "2.0s" || fmtDuration(5*time.Millisecond) != "5ms" || truncate("abc", 2) != "abc" {
		t.Error("helpers")
	}
}

func items() []Item {
	return []Item{
		{Name: "search", Kind: "read-only", Policy: "allowed"},
		{Name: "delete_all", Kind: "destructive", Policy: "opt-in"},
		{Name: "rename", Kind: "mutating", Policy: "opt-in"},
	}
}

func press(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+a":
		return tea.KeyMsg{Type: tea.KeyCtrlA}
	case "ctrl+n":
		return tea.KeyMsg{Type: tea.KeyCtrlN}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func loaded(t *testing.T) *selectorModel {
	t.Helper()
	m := NewSelectorModel(func() ([]Item, error) { return items(), nil })
	_ = m.Init()
	if v := m.View(); !strings.Contains(v, "Connecting and listing tools") {
		t.Errorf("loading view = %q", v)
	}
	next, _ := m.Update(fetchedItemsMsg{items: items()})
	return next.(*selectorModel)
}

func TestSelectorDefaultsKeysAndCommands(t *testing.T) {
	m := loaded(t)
	if !m.selected["search"] || m.selected["delete_all"] || m.selected["rename"] {
		t.Errorf("defaults follow policy: %v", m.selected)
	}
	v := m.View()
	for _, want := range []string{"Search tools (3 found)", "✔", "·", "[space]", "Made with ❤️ in London, UK"} {
		if !strings.Contains(v, want) {
			t.Errorf("view lacks %q", want)
		}
	}
	// filter
	for _, r := range "del" {
		next, _ := m.Update(press(string(r)))
		m = next.(*selectorModel)
	}
	if len(m.filtered) != 1 || m.filtered[0].Name != "delete_all" {
		t.Errorf("filter = %v", m.filtered)
	}
	next, _ := m.Update(press(" "))
	m = next.(*selectorModel)
	if !m.selected["delete_all"] {
		t.Error("space toggles the cursor row")
	}
	next, _ = m.Update(press("backspace"))
	m = next.(*selectorModel)
	next, _ = m.Update(press("backspace"))
	m = next.(*selectorModel)
	next, _ = m.Update(press("backspace"))
	m = next.(*selectorModel)
	if len(m.filtered) != 3 {
		t.Errorf("filter cleared: %d", len(m.filtered))
	}
	next, _ = m.Update(press("ctrl+n"))
	m = next.(*selectorModel)
	for _, it := range items() {
		if m.selected[it.Name] {
			t.Error("ctrl+n deselects all")
		}
	}
	next, _ = m.Update(press("ctrl+a"))
	m = next.(*selectorModel)
	if !m.selected["rename"] {
		t.Error("ctrl+a selects all")
	}
	// slash commands with completion
	for _, r := range "/so" {
		next, _ = m.Update(press(string(r)))
		m = next.(*selectorModel)
	}
	next, _ = m.Update(press("tab"))
	m = next.(*selectorModel)
	if m.filter != "/sort" {
		t.Errorf("tab completion = %q", m.filter)
	}
	if v := m.View(); !strings.Contains(v, "Command:") {
		t.Error("command prompt")
	}
	for _, r := range " kind" {
		next, _ = m.Update(press(string(r)))
		m = next.(*selectorModel)
	}
	next, _ = m.Update(press("enter"))
	m = next.(*selectorModel)
	if m.filtered[0].Kind != "destructive" || m.filter != "" {
		t.Errorf("sort kind: %v", m.filtered)
	}
	for _, c := range []string{"/sort name", "/sort read-only", "/sort policy", "/sort", "/sort bogus", "/none", "/all", "/wat", "/help"} {
		m.filter = c
		next, _ = m.Update(press("enter"))
		m = next.(*selectorModel)
	}
	if !m.showHelp || !strings.Contains(m.View(), "In-Session Commands") {
		t.Error("/help shows the panel")
	}
	next, _ = m.Update(press("esc"))
	m = next.(*selectorModel)
	if m.showHelp || m.quitting {
		t.Error("esc closes help first")
	}
	next, _ = m.Update(press("?"))
	m = next.(*selectorModel)
	if !m.showHelp {
		t.Error("? toggles help")
	}
	m.filter = "/sort bogus"
	next, _ = m.Update(press("enter"))
	m = next.(*selectorModel)
	if m.cmdErr == "" || !strings.Contains(m.View(), "Unknown sort field") {
		t.Error("bad sort reports an error")
	}
	// confirm
	m.filter = ""
	next, cmd := m.Update(press("enter"))
	m = next.(*selectorModel)
	if !m.confirmed || cmd == nil {
		t.Error("enter confirms")
	}
	m.filter = "/exit"
	next, _ = m.Update(press("enter"))
	m = next.(*selectorModel)
	if !m.quitting || m.confirmed {
		t.Error("/exit quits without confirming")
	}
	next, _ = m.Update(press("ctrl+c"))
	if !next.(*selectorModel).quitting {
		t.Error("ctrl+c quits")
	}
}

func TestSelectorLoadingGuardsAndErrors(t *testing.T) {
	m := NewSelectorModel(func() ([]Item, error) { return nil, errors.New("boom") })
	for _, k := range []string{"enter", " ", "backspace", "ctrl+a", "ctrl+n", "x", "?"} {
		next, _ := m.Update(press(k))
		m = next.(*selectorModel)
	}
	if m.filter != "" || m.confirmed {
		t.Error("keys are ignored while loading")
	}
	next, _ := m.Update(fetchedItemsMsg{err: errors.New("boom")})
	m = next.(*selectorModel)
	if m.loadingErr == nil || !strings.Contains(m.View(), "Error: boom") {
		t.Error("fetch error is shown")
	}
	if got, ok := completeSlashCommand("nope"); ok || got != "" {
		t.Error("completion only for slash commands")
	}
	if _, ok := completeSlashCommand("/all"); ok {
		t.Error("complete command has no completion")
	}
	Version = ""
	t.Cleanup(func() { Version = "dev" })
	if !strings.Contains(m.renderFooter(), "(vdev)") {
		t.Error("empty version renders as dev")
	}
}

func TestRunSelector(t *testing.T) {
	orig := runSelectorProgram
	defer func() { runSelectorProgram = orig }()
	runSelectorProgram = func(ctx context.Context, model tea.Model) (tea.Model, error) {
		m := model.(*selectorModel)
		next, _ := m.Update(fetchedItemsMsg{items: items()})
		m = next.(*selectorModel)
		m.selected["rename"] = true
		m.confirmed = true
		return m, nil
	}
	got, ok, err := RunSelector(context.Background(), func() ([]Item, error) { return items(), nil })
	if err != nil || !ok || len(got) != 2 {
		t.Fatalf("got %v %v %v", got, ok, err)
	}
	runSelectorProgram = func(ctx context.Context, model tea.Model) (tea.Model, error) {
		m := model.(*selectorModel)
		m.quitting = true
		m.loading = false
		return m, nil
	}
	if _, ok, err := RunSelector(context.Background(), nil); ok || err != nil {
		t.Error("quit without confirm")
	}
	runSelectorProgram = func(ctx context.Context, model tea.Model) (tea.Model, error) {
		m := model.(*selectorModel)
		m.loadingErr = errors.New("nope")
		return m, nil
	}
	if _, _, err := RunSelector(context.Background(), nil); err == nil {
		t.Error("loading error surfaces")
	}
	runSelectorProgram = func(ctx context.Context, model tea.Model) (tea.Model, error) { return nil, errors.New("tty") }
	if _, _, err := RunSelector(context.Background(), nil); err == nil {
		t.Error("program error surfaces")
	}
}
