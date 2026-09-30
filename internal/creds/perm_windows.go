// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package creds

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Windows has no Unix permission bits. Go synthesises a mode for every file
// it stats — 0666 for a regular file, 0444 when the read-only attribute is
// set — from the DOS attributes alone, and that value says nothing about
// who can read the file; testing it would reject every store. Access is
// governed by the file's access-control list, so that is what is read:
// the store is refused when the list lets any account other than the
// current user, the operating system or the local administrators read or
// change it (aclProblem, in perm_acl.go), and when the list cannot be
// read at all.
//
// golang.org/x/sys/windows is how the list is reached without cgo. It is
// already compiled into passmcp's Windows binary through the terminal
// libraries, so reading it adds no code to the build.

// checkStoreAccess refuses a store another account can read or change.
func checkStoreAccess(path string, _ os.FileInfo) error {
	reason, err := storeACLProblem(path)
	if err != nil {
		return fmt.Errorf("token store %s: its access control list could not be read, so it is not trusted: %w", path, err)
	}
	if reason != "" {
		return &ErrInsecurePermissions{Path: path, Reason: reason}
	}
	return nil
}

// storeACLProblem reads path's access-control list and says what is wrong
// with it, or "".
func storeACLProblem(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	self, err := currentUser()
	if err != nil {
		return "", err
	}
	sddl := sd.String()
	if sddl == "" {
		return "", errors.New("the security descriptor could not be rendered as SDDL")
	}
	present, null, entries := parseDACL(sddl, resolveSID)
	return aclProblem(present, null, entries, self.String()), nil
}

// resolveSID turns an SDDL SID field into a full SID string, asking
// Windows for an abbreviation the static table does not know (such as the
// machine's own Administrator account).
func resolveSID(s string) string {
	if strings.HasPrefix(s, "S-") {
		return s
	}
	if full := sddlSID(s); full != s {
		return full
	}
	if sid, err := windows.StringToSid(s); err == nil {
		return sid.String()
	}
	return s
}

// currentUser is the SID the process runs as.
func currentUser() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}

// restrictFile gives a new store file an access-control list of its own,
// protected from inheritance, that grants the current user and nobody
// else. Without it the file would inherit whatever its directory grants,
// and a store under a shared directory would be readable by others.
func restrictFile(f *os.File) error {
	self, err := currentUser()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(self),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
