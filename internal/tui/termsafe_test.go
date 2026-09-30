// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"errors"
	"strings"
	"testing"
)

// hostile is a server-chosen string that would rewrite the terminal.
const hostile = "\x1b[2J\x1b]0;owned\x07\rok\u009b1A"

func assertNoControls(t *testing.T, where, view string) {
	t.Helper()
	if i := strings.IndexAny(view, "\x1b\r\a\u009b"); i >= 0 {
		t.Errorf("%s carries a control character at %d: %q", where, i, view[max(0, i-20):min(len(view), i+20)])
	}
}

// TestRunViewNeutralisesServerText: a phase's status line can quote the
// server (its name, an error), and the live view draws it on the terminal.
func TestRunViewNeutralisesServerText(t *testing.T) {
	m := NewRunModel("http://x/mcp"+hostile, "none", []Phase{{"net", "Connectivity"}})
	next, _ := m.Update(PhaseDoneMsg{Name: "net", Action: "FAIL", Message: "server said" + hostile})
	v := next.(*RunModel).View()
	assertNoControls(t, "run view", v)
	if !strings.Contains(v, "server said") {
		t.Errorf("status line lost its text:\n%s", v)
	}
}

// TestSelectorNeutralisesToolNames: the selector lists tool names the
// server chose, and the name it hands back must still be the server's own,
// or the run would ask for a tool that does not exist.
func TestSelectorNeutralisesToolNames(t *testing.T) {
	m := NewSelectorModel(nil)
	next, _ := m.Update(fetchedItemsMsg{items: []Item{{Name: "evil" + hostile, Kind: "read-only", Policy: "allowed", Description: "d" + hostile}}})
	m = next.(*selectorModel)
	assertNoControls(t, "selector", m.View())
	if !strings.Contains(m.View(), "evil") {
		t.Error("tool name missing from the table")
	}
	if !m.selected["evil"+hostile] {
		t.Errorf("selection is keyed by the server's name: %v", m.selected)
	}

	failed := NewSelectorModel(nil)
	next, _ = failed.Update(fetchedItemsMsg{err: errors.New("listing failed:" + hostile)})
	assertNoControls(t, "selector error", next.(*selectorModel).View())
}
