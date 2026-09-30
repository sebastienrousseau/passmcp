// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package tui provides passmcp's Bubble Tea terminal user interface: a calm
// live progress view shown while a check runs, and the interactive tool
// selector. The report itself is printed to the terminal's own scrollback
// once the run finishes, so there is no viewport to fight and scrolling is
// the terminal's own.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"satellion.com/passmcp/internal/termsafe"
)

// Version is the build version. Injected at build time alongside
// cmd.Version.
var Version = "dev"

// Phase is one step of the run.
type Phase struct {
	Name  string
	Title string
}

// PhaseStartMsg marks a step as running.
type PhaseStartMsg struct{ Name string }

// PhaseDoneMsg records a step's outcome.
type PhaseDoneMsg struct {
	Name     string
	Action   string // PASS, WARN, FAIL or SKIP
	Duration time.Duration
	Message  string // a short, human status
}

// DoneMsg ends the run; the report is printed afterwards by the caller.
type DoneMsg struct{}

type step struct {
	Phase
	status   string // pending, running, PASS, WARN, FAIL, SKIP
	duration time.Duration
	message  string
}

var (
	accentC   = lipgloss.Color(Accent)
	brandS    = lipgloss.NewStyle().Bold(true).Foreground(accentC)
	titleS    = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	subtleS   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	faintS    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	passS     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnColor = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	failColor = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
)

// RunModel is the Bubble Tea model for a running check. It renders inline
// (no alt-screen), so the finished checklist stays in the scrollback above
// the printed report.
type RunModel struct {
	endpoint string
	subtitle string
	steps    []step
	spinner  spinner.Model
	width    int
	done     bool
	aborted  bool
	started  time.Time
	// Cancel is invoked when the user quits mid-run.
	Cancel func()
}

// NewRunModel builds the live view for the steps that will run. subtitle is
// a short, secret-free line under the endpoint (the credential mode).
func NewRunModel(endpoint, subtitle string, phases []Phase) *RunModel {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = lipgloss.NewStyle().Foreground(accentC)
	steps := make([]step, len(phases))
	for i, p := range phases {
		steps[i] = step{Phase: p, status: "pending"}
	}
	return &RunModel{endpoint: termsafe.String(endpoint), subtitle: termsafe.String(subtitle), steps: steps, spinner: sp, width: 80, started: time.Now()}
}

// Aborted reports whether the user quit before the run finished.
func (m *RunModel) Aborted() bool { return m.aborted }

// Init starts the spinner.
func (m *RunModel) Init() tea.Cmd { return m.spinner.Tick }

// Update handles run messages, resizes and the quit key.
func (m *RunModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case spinner.TickMsg:
		if m.done {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case PhaseStartMsg:
		m.setStep(msg.Name, func(st *step) { st.status = "running" })
		return m, nil
	case PhaseDoneMsg:
		// A status line can quote the server, and this is drawn on the
		// operator's terminal.
		m.setStep(msg.Name, func(st *step) {
			st.status, st.duration, st.message = msg.Action, msg.Duration, termsafe.String(msg.Message)
		})
		return m, nil
	case DoneMsg:
		m.done = true
		return m, tea.Quit
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// setStep applies set to every step with the given phase name.
func (m *RunModel) setStep(name string, set func(*step)) {
	for i := range m.steps {
		if m.steps[i].Name == name {
			set(&m.steps[i])
		}
	}
}

// handleKey quits on q, esc or ctrl+c, cancelling the run first when it
// has not finished; every other key is ignored.
func (m *RunModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		if !m.done {
			m.aborted = true
			if m.Cancel != nil {
				m.Cancel()
			}
		}
		return m, tea.Quit
	}
	return m, nil
}

// View renders the wordmark, the endpoint, the live checklist and a slim
// footer. No borders, generous spacing.
func (m *RunModel) View() string {
	var b strings.Builder
	b.WriteString("\n  " + brandS.Render("passmcp") + "\n")
	b.WriteString("  " + titleS.Render(m.endpoint) + "\n")
	if m.subtitle != "" {
		b.WriteString("  " + subtleS.Render(m.subtitle) + "\n")
	}
	b.WriteString("\n")

	labelW := 0
	for _, s := range m.steps {
		if w := lipgloss.Width(s.Title); w > labelW {
			labelW = w
		}
	}
	for _, s := range m.steps {
		b.WriteString("  " + m.stepLine(s, labelW) + "\n")
	}

	switch {
	case m.aborted:
		b.WriteString("\n  " + failColor.Render("Stopped.") + "\n")
	case !m.done:
		done := 0
		for _, s := range m.steps {
			if s.status != "pending" && s.status != "running" {
				done++
			}
		}
		b.WriteString("\n  " + subtleS.Render(fmt.Sprintf("%d of %d phases", done, len(m.steps))) +
			faintS.Render("   ·   press ") + subtleS.Render("q") + faintS.Render(" to stop") + "\n")
	}
	return b.String()
}

func (m *RunModel) stepLine(s step, labelW int) string {
	var icon, label string
	switch s.status {
	case "pending":
		icon, label = faintS.Render("○"), faintS.Render(s.Title)
	case "running":
		icon, label = m.spinner.View(), titleS.Render(s.Title)
	case "PASS":
		icon, label = passS.Render("✓"), titleS.Render(s.Title)
	case "WARN":
		icon, label = warnColor.Render("△"), titleS.Render(s.Title)
	case "FAIL":
		icon, label = failColor.Render("✕"), titleS.Render(s.Title)
	default: // SKIP
		icon, label = faintS.Render("–"), faintS.Render(s.Title)
	}
	pad := strings.Repeat(" ", max(0, labelW-lipgloss.Width(s.Title)))
	line := icon + "  " + label + pad
	switch {
	case s.status == "running":
		line += "   " + subtleS.Render("checking…")
	case s.status != "pending" && s.message != "":
		msgW := max(12, m.width-labelW-16)
		line += "   " + subtleS.Render(truncate(s.message, msgW))
		if s.duration > 0 && (s.status == "PASS" || s.status == "WARN" || s.status == "FAIL") {
			line += faintS.Render("  " + fmtDuration(s.duration))
		}
	}
	return line
}

// ResultIcon is the single-character marker for non-TTY log lines.
func ResultIcon(action string) string {
	switch action {
	case "FAIL", "ERROR":
		return "✕"
	case "SKIP":
		return "–"
	case "WARN":
		return "△"
	}
	return "✓"
}

func fmtDuration(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func truncate(s string, n int) string {
	if n < 4 {
		n = 4
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
