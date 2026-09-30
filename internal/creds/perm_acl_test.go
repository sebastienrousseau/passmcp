// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"strings"
	"testing"
)

const testSelf = "S-1-5-21-1-2-3-1001"

// storeVerdict runs the Windows check on an SDDL string, as Windows would
// render a store's access-control list.
func storeVerdict(sddl string) string {
	present, null, entries := parseDACL(sddl, sddlSID)
	return aclProblem(present, null, entries, testSelf)
}

// TestACLProblemRefusesAStoreAnotherAccountCanRead is the Windows
// counterpart of the Unix 0600 test, run on every platform: the decision
// is made from the access-control list alone. Before it, a store on
// Windows was used whatever its list granted.
func TestACLProblemRefusesAStoreAnotherAccountCanRead(t *testing.T) {
	for name, tc := range map[string]struct{ sddl, want string }{
		"no list":                   {"O:BAG:SY", "no access control list"},
		"NULL list":                 {"D:NO_ACCESS_CONTROL", "no access control list"},
		"Everyone may read":         {"D:P(A;;FA;;;" + testSelf + ")(A;;FR;;;WD)", "S-1-1-0"},
		"Users inherit read":        {"D:AI(A;;FA;;;" + testSelf + ")(A;ID;0x1200a9;;;S-1-5-32-545)", "S-1-5-32-545"},
		"Authenticated Users write": {"D:(A;;FW;;;AU)", "S-1-5-11"},
		"another user":              {"D:(A;;FA;;;S-1-5-21-1-2-3-1002)", "1002"},
		"another may re-grant":      {"D:(A;;WD;;;S-1-5-21-9)", "S-1-5-21-9"},
		"object allow":              {"D:(OA;;FA;;;" + testSelf + ")", "does not evaluate"},
		"unknown right":             {"D:(A;;ZZ;;;WD)", "S-1-1-0"},
		"malformed hex right":       {"D:(A;;0xZZ;;;WD)", "S-1-1-0"},
		"odd-length rights":         {"D:(A;;FAR;;;WD)", "S-1-1-0"},
		"truncated entry":           {"D:(A;;FA)", "does not evaluate"},
		"unknown alias":             {"D:(A;;FA;;;LA)", "LA"},
	} {
		got := storeVerdict(tc.sddl)
		if got == "" || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q gave %q, want it to mention %q", name, tc.sddl, got, tc.want)
		}
	}

	for name, sddl := range map[string]string{
		"owner only":                    "D:P(A;;FA;;;" + testSelf + ")",
		"a profile's usual three":       "D:PAI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;" + testSelf + ")",
		"empty list denies everybody":   "D:P",
		"deny entries take away":        "D:(A;;FA;;;" + testSelf + ")(D;;FA;;;WD)",
		"inherit-only reaches children": "D:(A;;FA;;;" + testSelf + ")(A;OICIIO;GA;;;CO)",
		"attributes only":               "D:(A;;FA;;;" + testSelf + ")(A;;0x80;;;WD)",
		"with a SACL after it":          "D:P(A;;FA;;;" + testSelf + ")S:(AU;FA;FA;;;WD)",
	} {
		if got := storeVerdict(sddl); got != "" {
			t.Errorf("%s: %q refused: %s", name, sddl, got)
		}
	}
}
