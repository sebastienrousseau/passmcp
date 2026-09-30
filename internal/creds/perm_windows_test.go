// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package creds

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestStoreIsWrittenForTheCurrentUserOnly: a store Put creates grants the
// current user and nobody else, whatever the directory it is in grants.
func TestStoreIsWrittenForTheCurrentUserOnly(t *testing.T) {
	s := tempStore(t)
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if reason, err := storeACLProblem(s.Path); err != nil || reason != "" {
		t.Fatalf("a freshly written store is not private: %q, %v", reason, err)
	}
	if _, err := s.Get("https://a/mcp"); err != nil {
		t.Fatalf("a freshly written store was refused: %v", err)
	}
}

// TestStoreRefusesAnACLThatGrantsEveryone is the Windows counterpart of
// TestStoreRefusesWorldReadableFile: before the check, a store any
// account could read was used as if the filesystem had vouched for it.
func TestStoreRefusesAnACLThatGrantsEveryone(t *testing.T) {
	s := tempStore(t)
	if err := s.Put(StoredToken{Endpoint: "https://a/mcp", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(s.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	widened, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(s.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, widened, nil); err != nil {
		t.Fatal(err)
	}
	var insecure *ErrInsecurePermissions
	_, err = s.Get("https://a/mcp")
	if !errors.As(err, &insecure) || !strings.Contains(err.Error(), everyone.String()) || !strings.Contains(err.Error(), "icacls") {
		t.Fatalf("a store Everyone can read must be refused with the fix, got %v", err)
	}
}
