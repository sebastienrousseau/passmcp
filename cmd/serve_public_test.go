// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// --public is the difference between a diagnostic on your own machine and
// one answering the open internet. Every way of starting it wrong has to
// fail before the listener exists, because there is no second chance once
// it is accepting requests.
//
// Only the refusals are exercised here: a --public server that starts
// correctly blocks until its context ends, and internal/web covers what it
// does once running.

func TestServePublicRefusesToStartWithoutAnAllowlist(t *testing.T) {
	_, code := run(t, "serve", "--public")
	if code == 0 {
		t.Fatal("--public without --allow-file must not start a listener")
	}
}

func TestServePublicRefusesABadAllowlist(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.json")
	if _, code := run(t, "serve", "--public", "--allow-file", missing); code == 0 {
		t.Error("a missing allowlist file must not start a listener")
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"servers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, "serve", "--public", "--allow-file", empty); code == 0 {
		t.Error("an empty allowlist must not read as permission to scan anything")
	}

	unsafe := filepath.Join(dir, "unsafe.json")
	if err := os.WriteFile(unsafe, []byte(`{"servers":[{"name":"x","endpoint":"http://169.254.169.254/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, "serve", "--public", "--allow-file", unsafe); code == 0 {
		t.Error("a plaintext link-local entry must not be allowlistable")
	}
}

// The overrides that make local debugging pleasant are the ones that make a
// public deployment dangerous. Combining them must fail loudly rather than
// be quietly ignored.
func TestServePublicRefusesTheInsecureOverrides(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "list.json")
	if err := os.WriteFile(list, []byte(`{"servers":[{"name":"x","endpoint":"https://mcp.example.com/mcp"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{
		"--insecure-allow-private-hosts",
		"--insecure-allow-http-auth",
		"--allow-resource-mismatch",
	} {
		_, code := run(t, "serve", "--public", "--allow-file", list, flag)
		if code == 0 {
			t.Errorf("%s must not be combinable with --public", flag)
		}
	}
}
