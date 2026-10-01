// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package tui

import (
	"fmt"
	"strings"
	"testing"
)

// TestExecuteSlashCommand pins every outcome of an in-session command on
// the model's whole state: the order of the filtered list, the selection,
// the error line, the help panel, quitting, whether the table rows were
// rebuilt, and whether a command was returned. The end-to-end key test in
// tui_test.go drives the same commands through Update but only looks at a
// few of these.
func TestExecuteSlashCommand(t *testing.T) {
	list := []Item{
		{Name: "search", Kind: "read-only", Policy: "allowed"},
		{Name: "delete_all", Kind: "destructive", Policy: "opt-in"},
		{Name: "Archive", Kind: "mutating", Policy: "opt-in"},
		{Name: "rename", Kind: "mutating", Policy: "allowed"},
		{Name: "lookup", Kind: "read-only", Policy: "opt-in"},
	}
	type want struct {
		order    string
		selected string
		cmdErr   string
		help     bool
		quit     bool
		rows     bool
		cmd      bool
	}
	unsorted := "search delete_all Archive rename lookup"
	cases := []struct {
		in   string
		want want
	}{
		{"", want{order: unsorted}},
		{"   ", want{order: unsorted}},
		{"/exit", want{order: unsorted, quit: true, cmd: true}},
		{"/quit", want{order: unsorted, quit: true, cmd: true}},
		{"/help", want{order: unsorted, help: true}},
		{"/all", want{order: unsorted, selected: "Archive delete_all lookup rename search", rows: true}},
		{"/none", want{order: unsorted, rows: true}},
		{"/sort", want{order: unsorted, cmdErr: "Usage: /sort <name|kind|policy|read-only|mutating|destructive>"}},
		{"/sort name", want{order: "Archive delete_all lookup rename search", rows: true}},
		{"/sort NAME", want{order: "Archive delete_all lookup rename search", rows: true}},
		{"/sort kind", want{order: "delete_all Archive rename search lookup", rows: true}},
		{"/sort policy", want{order: "search rename delete_all Archive lookup", rows: true}},
		{"/sort read-only", want{order: "lookup search Archive delete_all rename", rows: true}},
		{"/sort readonly", want{order: "lookup search Archive delete_all rename", rows: true}},
		{"/sort mutating", want{order: "Archive rename delete_all lookup search", rows: true}},
		{"/sort destructive", want{order: "delete_all Archive lookup rename search", rows: true}},
		{"/sort Bogus", want{order: unsorted, rows: true,
			cmdErr: "Unknown sort field: Bogus (choose name, kind, policy, read-only, mutating or destructive)"}},
		{"/wat now", want{order: unsorted, cmdErr: "Unknown command: /wat. Type /help for help."}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			m := loaded(t)
			m.filtered = append([]Item(nil), list...)
			m.selected = map[string]bool{}
			m.cmdErr = "stale"
			m.table.SetRows(nil)

			cmd := m.executeSlashCommand(tc.in)

			var order, selected []string
			for _, it := range m.filtered {
				order = append(order, it.Name)
			}
			for _, it := range []string{"Archive", "delete_all", "lookup", "rename", "search"} {
				if m.selected[it] {
					selected = append(selected, it)
				}
			}
			got := want{
				order:    strings.Join(order, " "),
				selected: strings.Join(selected, " "),
				cmdErr:   m.cmdErr,
				help:     m.showHelp,
				quit:     m.quitting && !m.confirmed,
				rows:     len(m.table.Rows()) == len(list),
				cmd:      cmd != nil,
			}
			if got != tc.want {
				t.Errorf("\n got %s\nwant %s", fmt.Sprintf("%+v", got), fmt.Sprintf("%+v", tc.want))
			}
		})
	}
}
