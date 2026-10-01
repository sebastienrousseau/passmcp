// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// slashCommands are the in-session commands the filter line accepts.
var slashCommands = []string{"/exit", "/quit", "/help", "/all", "/none", "/sort"}

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

// executeSlashCommand runs one in-session command and clears the previous
// command's error.
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
		m.selectFiltered(true)
	case "/none":
		m.selectFiltered(false)
	case "/sort":
		m.sortCommand(parts)
	default:
		m.cmdErr = fmt.Sprintf("Unknown command: %s. Type /help for help.", parts[0])
	}
	return nil
}

// selectFiltered selects or deselects every tool the filter shows.
func (m *selectorModel) selectFiltered(on bool) {
	for _, it := range m.filtered {
		m.selected[it.Name] = on
	}
	m.updateTableRows()
}

// sortCommand runs /sort <field>.
func (m *selectorModel) sortCommand(parts []string) {
	if len(parts) < 2 {
		m.cmdErr = "Usage: /sort <name|kind|policy|read-only|mutating|destructive>"
		return
	}
	if less := m.sortLess(strings.ToLower(parts[1])); less != nil {
		sort.SliceStable(m.filtered, less)
	} else {
		m.cmdErr = fmt.Sprintf("Unknown sort field: %s (choose name, kind, policy, read-only, mutating or destructive)", parts[1])
	}
	m.updateTableRows()
}

// sortLess is the ordering /sort applies for a lower-cased field, or nil
// for a field it does not know.
func (m *selectorModel) sortLess(field string) func(i, j int) bool {
	switch field {
	case "name":
		return func(i, j int) bool { return strings.ToLower(m.filtered[i].Name) < strings.ToLower(m.filtered[j].Name) }
	case "kind":
		return func(i, j int) bool { return m.filtered[i].Kind < m.filtered[j].Kind }
	case "policy":
		return func(i, j int) bool { return m.filtered[i].Policy < m.filtered[j].Policy }
	case "read-only", "readonly", "mutating", "destructive":
		want := strings.ReplaceAll(field, "readonly", "read-only")
		return func(i, j int) bool {
			iK, jK := m.filtered[i].Kind == want, m.filtered[j].Kind == want
			if iK != jK {
				return iK
			}
			return strings.ToLower(m.filtered[i].Name) < strings.ToLower(m.filtered[j].Name)
		}
	}
	return nil
}
