// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"context"
	"strings"
	"testing"
	"time"
)

// rpcErrorFromTree must say exactly what rpcErrorFromBody says about the
// same body, including where encoding/json is lenient or strict.
func TestRPCErrorFromTreeMatchesBody(t *testing.T) {
	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`,
		`{"error":{"code":-32601}}`,
		`{"error":{"message":"only a message"}}`,
		`{"error":{}}`,
		`{"error":null}`,
		`{"error":"a string"}`,
		`{"error":[1,2]}`,
		`{"error":{"code":1.5,"message":"x"}}`,
		`{"error":{"code":1e2,"message":"x"}}`,
		`{"error":{"code":99999999999999999999,"message":"x"}}`,
		`{"error":{"code":"-1","message":"x"}}`,
		`{"error":{"code":null,"message":null}}`,
		`{"error":{"code":1,"message":7}}`,
		`{"Error":{"code":2,"message":"case"}}`,
		`{"error":{"code":1,"message":"a"},"ERROR":null}`,
		`{"error":{"Code":3,"MESSAGE":"case"}}`,
		`{"error":{"code":1,"code":2,"message":"dup"}}`,
		`{"error":{"code":1},"error":{"code":2}}`,
		`{"result":{}}`,
		`[{"error":{"code":1}}]`,
		`"error"`,
		`null`,
	}
	for _, body := range bodies {
		tree, ok := decodeJSON([]byte(body))
		if !ok {
			t.Fatalf("fixture %s does not decode", body)
		}
		gc, gm, gok := rpcErrorFromTree(tree, []byte(body))
		wc, wm, wok := rpcErrorFromBody([]byte(body))
		if gc != wc || gm != wm || gok != wok {
			t.Errorf("%s: tree gives (%d, %q, %t), body gives (%d, %q, %t)", body, gc, gm, gok, wc, wm, wok)
		}
	}
}

// A body that is not captured is never rendered, so the personal values in
// it were not masked anywhere and must not be counted as masked. They are
// still registered, so a later place that repeats one masks it.
func TestUncapturedBodyRegistersWithoutCounting(t *testing.T) {
	rec := New()
	sent := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"who"}}`)
	got := []byte(`{"jsonrpc":"2.0","id":1,"result":{"full_name":"Ada Lovelace","access_token":"issued-in-a-result"}}`)
	rec.RecordPipe(context.Background(), "server", sent, got, time.Millisecond, nil)
	if n := rec.Redactor.Summary().PersonalData["field"]; n != 0 {
		t.Errorf("counted %d masked fields for a body that was not recorded", n)
	}
	if s := rec.Redactor.Text("Ada Lovelace holds issued-in-a-result"); strings.Contains(s, "Ada") || strings.Contains(s, "issued") {
		t.Errorf("values in the uncaptured body were not registered: %q", s)
	}
	if n := rec.Redactor.Summary().PersonalData["field"]; n != 1 {
		t.Errorf("counted %d masked fields after masking one, want 1", n)
	}
}

// Capturing reuses the decoded body, so the rendered body must be what
// masking a fresh decode renders, and the RPC error must still be found.
func TestCapturedResponseUsesOneDecode(t *testing.T) {
	rec := New()
	rec.CaptureBodies = true
	sent := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"who"}}`)
	got := []byte(`{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"denied"},"data":{"client_secret":"issued-secret-value","n":9007199254740993}}`)
	rec.RecordPipe(context.Background(), "server", sent, got, time.Millisecond, nil)
	ev := rec.Events()[0]
	if ev.RPC.ErrorCode != -32000 || ev.RPC.ErrorMessage != "denied" {
		t.Errorf("rpc = %+v", ev.RPC)
	}
	if want := (&Redactor{}).JSON(got); ev.ResponseBody != want {
		t.Errorf("body = %s, want %s", ev.ResponseBody, want)
	}
	if strings.Contains(ev.ResponseBody, "issued-secret-value") || rec.Redactor.String("issued-secret-value") != Mask {
		t.Errorf("issued secret not masked and registered: %s", ev.ResponseBody)
	}
}
