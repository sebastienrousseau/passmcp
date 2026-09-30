// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"fmt"
	"strconv"
	"strings"
)

// The Windows half of the token store's access check decides from the
// file's access-control list, read as the SDDL string Windows renders it
// as. Parsing and judging are here, free of any Windows API, so they are
// tested on every platform CI runs; perm_windows.go only asks Windows for
// the string and for the current user's SID.

// aceKind is the type of an access-control entry, as far as the check
// needs to know it.
type aceKind int

const (
	aceAllow aceKind = iota // "A": ACCESS_ALLOWED_ACE_TYPE
	aceDeny                 // "D": ACCESS_DENIED_ACE_TYPE
	aceOther                // any other type, including object and callback allows
)

// aclEntry is one access-control entry: whether it grants or denies, the
// rights, to whom (a SID in string form), and whether it only passes to
// children rather than applying to the file itself.
type aclEntry struct {
	Kind        aceKind
	InheritOnly bool
	Mask        uint32
	SID         string
}

// Access rights that let an account read or change the store, or change
// who may. The values are Windows' own (winnt.h).
const (
	fileReadData   = 0x00000001
	fileWriteData  = 0x00000002
	fileAppendData = 0x00000004
	writeDAC       = 0x00040000
	writeOwner     = 0x00080000
	genericAll     = 0x10000000
	genericWrite   = 0x40000000
	genericRead    = 0x80000000

	storeRights = fileReadData | fileWriteData | fileAppendData | writeDAC | writeOwner |
		genericAll | genericWrite | genericRead
)

// Well-known SIDs that may hold the store's rights without making it
// readable by another user: the operating system itself and the local
// administrators, both of whom can take any file on the machine anyway.
const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// sddlRights are the two-letter access codes an SDDL ACE string may use,
// with the bits each stands for.
var sddlRights = map[string]uint32{
	"GA": genericAll, "GR": genericRead, "GW": genericWrite, "GX": 0x20000000,
	"RC": 0x00020000, "SD": 0x00010000, "WD": writeDAC, "WO": writeOwner,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
	"FA": 0x001F01FF, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200A0,
	"KA": 0x000F003F, "KR": 0x00020019, "KW": 0x00020006, "KX": 0x00020019,
}

// sddlAliases are the SID abbreviations SDDL uses for well-known accounts
// that do not depend on the machine or domain. One not listed here is
// kept as written, which no trusted SID matches.
var sddlAliases = map[string]string{
	"SY": sidLocalSystem, "BA": sidAdministrators, "WD": "S-1-1-0", "AU": "S-1-5-11",
	"BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "AN": "S-1-5-7", "IU": "S-1-5-4",
	"NU": "S-1-5-2", "SU": "S-1-5-6", "LS": "S-1-5-19", "NS": "S-1-5-20",
	"CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4", "RC": "S-1-5-12",
}

// sddlSID resolves an SDDL SID field through sddlAliases.
func sddlSID(s string) string {
	if full, ok := sddlAliases[s]; ok {
		return full
	}
	return s
}

// parseDACL reads the discretionary ACL out of an SDDL string. present is
// false when there is no "D:" part, and null true for NO_ACCESS_CONTROL;
// resolve turns an SID field into a full SID string.
func parseDACL(sddl string, resolve func(string) string) (present, null bool, entries []aclEntry) {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return false, false, nil
	}
	d := sddl[i+2:]
	if j := strings.Index(d, "S:"); j >= 0 {
		d = d[:j]
	}
	if strings.Contains(d, "NO_ACCESS_CONTROL") {
		return true, true, nil
	}
	for _, part := range strings.Split(d, "(")[1:] {
		entries = append(entries, parseACE(strings.TrimSuffix(part, ")"), resolve))
	}
	return true, false, entries
}

// parseACE reads one "type;flags;rights;object;inherited-object;sid" ACE
// string. A field it cannot read makes an entry of kind aceOther with
// every right, so the check refuses rather than guesses.
func parseACE(s string, resolve func(string) string) aclEntry {
	f := strings.Split(s, ";")
	if len(f) < 6 {
		return aclEntry{Kind: aceOther, Mask: ^uint32(0)}
	}
	e := aclEntry{Kind: aceOther, InheritOnly: hasCode(f[1], "IO"), Mask: sddlMask(f[2]), SID: resolve(f[5])}
	switch f[0] {
	case "A":
		e.Kind = aceAllow
	case "D":
		e.Kind = aceDeny
	}
	return e
}

// hasCode reports whether a string of two-letter codes contains code.
func hasCode(codes, code string) bool {
	for i := 0; i+2 <= len(codes); i += 2 {
		if codes[i:i+2] == code {
			return true
		}
	}
	return false
}

// sddlMask reads a rights field: a number, or a run of two-letter codes.
// An unknown code counts as every right.
func sddlMask(s string) uint32 {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if v, err := strconv.ParseUint(s, 0, 32); err == nil {
			return uint32(v)
		}
		return ^uint32(0)
	}
	var mask uint32
	for i := 0; i+2 <= len(s); i += 2 {
		bits, ok := sddlRights[s[i:i+2]]
		if !ok {
			return ^uint32(0)
		}
		mask |= bits
	}
	if len(s)%2 != 0 {
		return ^uint32(0)
	}
	return mask
}

// aclProblem says why a file's access-control list lets an account other
// than self read or change it, or returns "" when it does not.
//
// present is false for a file with no list at all, and null true for one
// whose list is NULL; Windows grants everyone full access in both cases.
// An allow entry of a type this check does not evaluate is a problem too:
// it fails closed rather than guessing what the entry grants. Deny
// entries only take access away, so they cannot make a store unsafe and
// are skipped, as are entries that apply only to children.
func aclProblem(present, null bool, entries []aclEntry, self string) string {
	if !present || null {
		return "has no access control list, so every account on this machine can read it"
	}
	for _, e := range entries {
		if e.InheritOnly || e.Kind == aceDeny || e.Mask&storeRights == 0 {
			continue
		}
		if e.Kind == aceOther {
			return "carries an access control entry of a kind passmcp does not evaluate"
		}
		if !trustedSID(e.SID, self) {
			return fmt.Sprintf("grants access (mask %#x) to %s", e.Mask, e.SID)
		}
	}
	return ""
}

// trustedSID reports whether sid may hold the store's rights.
func trustedSID(sid, self string) bool {
	return sid == self || sid == sidLocalSystem || sid == sidAdministrators
}
