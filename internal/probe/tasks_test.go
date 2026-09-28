// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/creds"
)

// Each case is one way a server can get the Tasks extension wrong, run
// against the stateless fake with that one knob on. The expectation names
// the check the defect must land on, its status, and a phrase the detail
// has to contain, so a finding that lands on the right check for the wrong
// reason still fails.

type taskWant struct {
	id     string
	status Status
	phrase string
}

func runTasks(t *testing.T, k *taskKnobs) *Session {
	t.Helper()
	return runStateless(t, statelessFake(t, statelessOpts{tasks: k}), func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "protocol", "catalog", "execution"}
	})
}

func expectTask(t *testing.T, s *Session, wants ...taskWant) {
	t.Helper()
	for _, w := range wants {
		f, ok := findingByID(s, w.id)
		if !ok {
			t.Errorf("%s is missing", w.id)
			continue
		}
		if f.Status != w.status || !strings.Contains(f.Detail, w.phrase) {
			t.Errorf("%s = %s %q, want %s containing %q", w.id, f.Status, f.Detail, w.status, w.phrase)
		}
	}
}

// TestACorrectTasksServerPassesEveryCheck. The zero knobs are a conformant
// implementation, and a conformant implementation must not be reported.
func TestACorrectTasksServerPassesEveryCheck(t *testing.T) {
	k := &taskKnobs{}
	s := runTasks(t, k)
	if k.cancels != 0 {
		t.Errorf("passmcp cancelled a task that completed on its own (%d cancels)", k.cancels)
	}
	expectTask(t, s,
		taskWant{"protocol.tasks.unknown_id", Pass, "-32602"},
		taskWant{"protocol.tasks.capability", Pass, "-32021"},
		taskWant{"protocol.tasks.undeclared", Pass, "synchronously"},
		taskWant{"protocol.tasks.lifecycle", Pass, "reached completed"},
	)
	if f, _ := findingByID(s, "protocol.tasks.lifecycle"); len(f.Evidence) == 0 {
		t.Error("the lifecycle verdict cites no requests")
	}
}

func TestTasksMisbehaviours(t *testing.T) {
	orig := taskPollBudget
	taskPollBudget = 1500 * time.Millisecond
	t.Cleanup(func() { taskPollBudget = orig })

	for name, tc := range map[string]struct {
		k      taskKnobs
		want   taskWant
		cancel bool // passmcp must cancel the task it started
	}{
		"answers an unknown id":         {taskKnobs{unknownOK: true}, taskWant{"protocol.tasks.unknown_id", Fail, "never issued as if it existed"}, false},
		"wrong code for an unknown id":  {taskKnobs{wrongCode: true}, taskWant{"protocol.tasks.unknown_id", Warn, "error -32603"}, false},
		"ignores the capability":        {taskKnobs{ignoreCapability: true}, taskWant{"protocol.tasks.capability", Warn, "not -32021"}, false},
		"a task nobody asked for":       {taskKnobs{undeclared: true}, taskWant{"protocol.tasks.undeclared", Fail, "did not declare"}, false},
		"answers synchronously":         {taskKnobs{sync: true}, taskWant{"protocol.tasks.lifecycle", Skip, "no lifecycle to follow"}, false},
		"handle before the task exists": {taskKnobs{notDurable: true}, taskWant{"protocol.tasks.lifecycle", Fail, "not retrievable immediately"}, false},
		"never finishes":                {taskKnobs{neverEnds: true}, taskWant{"protocol.tasks.lifecycle", Warn, "cancellation acknowledged"}, true},
		"asks for input":                {taskKnobs{inputRequired: true}, taskWant{"protocol.tasks.lifecycle", Info, "input_required"}, true},
		"completed with no result":      {taskKnobs{noResult: true}, taskWant{"protocol.tasks.lifecycle", Fail, "no result object"}, true},
		"no ttlMs":                      {taskKnobs{noTTL: true}, taskWant{"protocol.tasks.lifecycle", Fail, "no ttlMs"}, true},
		"a terminal state that changes": {taskKnobs{flip: true}, taskWant{"protocol.tasks.lifecycle", Fail, "terminal states must not change"}, false},
		"declaring breaks the call":     {taskKnobs{declaredFails: true}, taskWant{"protocol.tasks.lifecycle", Warn, "succeeds without it"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			k := tc.k
			expectTask(t, runTasks(t, &k), tc.want)
			if got := k.cancels > 0; got != tc.cancel {
				t.Errorf("passmcp sent %d tasks/cancel; want a cancel: %v", k.cancels, tc.cancel)
			}
		})
	}
}

// TestTasksAreSkippedByName where they cannot apply: a server that does not
// advertise the extension, and a server on a handshake revision.
func TestTasksAreSkippedByName(t *testing.T) {
	s := runStateless(t, statelessFake(t, statelessOpts{}), nil)
	ids := []string{"protocol.tasks.unknown_id", "protocol.tasks.capability", "protocol.tasks.undeclared", "protocol.tasks.lifecycle"}
	for _, id := range ids {
		expectTask(t, s, taskWant{id, Skip, "does not advertise"})
	}

	f := newFakeServer(t)
	f.acceptAnyToken = true
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, nil)
	for _, id := range ids {
		expect(t, fs, id, Skip, "different mechanism")
	}
}

func TestTaskHelpers(t *testing.T) {
	ten, big := 10.0, 60000.0
	for _, tc := range []struct {
		in   *float64
		want time.Duration
	}{{nil, taskPollDefault}, {&ten, taskPollMin}, {&big, taskPollMax}} {
		if got := (taskState{PollIntervalMs: tc.in}).interval(); got != tc.want {
			t.Errorf("interval(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
	bad := taskState{TaskID: "x", Status: "nearly", CreatedAt: "yesterday", LastUpdatedAt: "2026-09-23T10:00:00Z", TTL: []byte(`"soon"`)}
	got := strings.Join(bad.shapeProblems("t"), "; ")
	for _, want := range []string{`status "nearly"`, "no ISO 8601 createdAt", "neither a number nor null"} {
		if !strings.Contains(got, want) {
			t.Errorf("shapeProblems missed %q: %s", want, got)
		}
	}
	if p := (taskState{TaskID: "x", Status: "failed", CreatedAt: "2026-09-23T10:00:00Z", LastUpdatedAt: "2026-09-23T10:00:00Z", TTL: []byte("null")}).shapeProblems("t"); len(p) != 1 || !strings.Contains(p[0], "no error object") {
		t.Errorf("failed with no error: %v", p)
	}
	if got := dedupeStrings([]string{"a", "b", "a"}); got != "a; b" {
		t.Errorf("dedupeStrings = %q", got)
	}
	if shortTrace(&Session{TraceID: "abc"}) != "abc" {
		t.Error("shortTrace on a short id")
	}
}
