// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package telemetry

import (
	"math/rand/v2"
	"net/url"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// oracle is the redactor's masking as it was written before it was made
// search-first: one strings.ReplaceAll per secret, raw then URL-escaped,
// longest secret first, then one Count and ReplaceAll per personal value,
// longest first. It is kept verbatim as the reference the faster code is
// held to, with one difference: the original sorted secrets with
// sort.Slice, which leaves secrets of equal length in no defined order;
// this uses the stable order (first registered first) that the new code
// guarantees.
type oracle struct {
	secrets, personal []string
}

func (o *oracle) add(secret string) {
	if len(secret) < 4 {
		return
	}
	for _, s := range o.secrets {
		if s == secret {
			return
		}
	}
	o.secrets = append(o.secrets, secret)
	sort.SliceStable(o.secrets, func(i, j int) bool { return len(o.secrets[i]) > len(o.secrets[j]) })
}

func (o *oracle) addPersonal(v string) {
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) < minPersonal || v == Mask {
		return
	}
	for _, p := range o.personal {
		if p == v {
			return
		}
	}
	o.personal = append(o.personal, v)
	for i := len(o.personal) - 1; i > 0 && len(o.personal[i]) > len(o.personal[i-1]); i-- {
		o.personal[i], o.personal[i-1] = o.personal[i-1], o.personal[i]
	}
}

// str returns what String returned, and how many personal values it
// counted.
func (o *oracle) str(s string) (string, int) {
	for _, sec := range o.secrets {
		s = strings.ReplaceAll(s, sec, Mask)
		if esc := url.QueryEscape(sec); esc != sec {
			s = strings.ReplaceAll(s, esc, Mask)
		}
	}
	fields := 0
	for _, p := range o.personal {
		if n := strings.Count(s, p); n > 0 {
			fields += n
			s = strings.ReplaceAll(s, p, Mask)
		}
	}
	return s, fields
}

// equivCase registers secrets and personal values in both the redactor and
// the oracle and compares String and the field count on each text.
// It reports whether either list was large enough to be searched in one
// pass before replacing.
func equivCase(t *testing.T, secrets, personal, texts []string) bool {
	t.Helper()
	r, o := &Redactor{}, &oracle{}
	for _, s := range secrets {
		r.Add(s)
		o.add(s)
	}
	for _, p := range personal {
		r.addPersonal(p)
		o.addPersonal(p)
	}
	for _, text := range texts {
		before := r.Summary().PersonalData["field"]
		got := r.String(text)
		want, fields := o.str(text)
		if got != want {
			t.Fatalf("secrets %q personal %q\ntext %q\n got %q\nwant %q", secrets, personal, text, got, want)
		}
		if n := r.Summary().PersonalData["field"] - before; n != fields {
			t.Fatalf("secrets %q personal %q text %q: counted %d fields, oracle %d", secrets, personal, text, n, fields)
		}
	}
	return len(r.secretMask.byID) > seqMax || len(r.personalMask.byID) > seqMax
}

// randString draws n bytes from alphabet.
func randString(rng *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}

// randText builds a text out of whole values, their escaped forms,
// fragments of them and noise, so that matches abut, nest and overlap.
func randText(rng *rand.Rand, alphabet string, values []string) string {
	var b strings.Builder
	for range rng.IntN(24) {
		v := ""
		if len(values) > 0 {
			v = values[rng.IntN(len(values))]
		}
		switch rng.IntN(5) {
		case 0:
			b.WriteString(v)
		case 1:
			b.WriteString(url.QueryEscape(v))
		case 2:
			if len(v) > 1 {
				i := rng.IntN(len(v))
				b.WriteString(v[i:])
			}
		case 3:
			b.WriteString(Mask[:rng.IntN(len(Mask)+1)])
		default:
			b.WriteString(randString(rng, alphabet, rng.IntN(6)))
		}
	}
	return b.String()
}

// TestRedactorMatchesOracle holds the search-first redactor to the
// sequential one it replaced, over secret sets chosen to collide: a tiny
// alphabet makes prefixes, suffixes, nesting, repeated characters,
// characters that URL-escape, and '*' (the mask's own character) common.
// Token-shaped sets are added for realism. Sets range from empty to 39
// values, so both the plain sequential path and the search-first path run.
func TestRedactorMatchesOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	const colliding = "ab/ %*2F+"
	const tokens = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	found, sequential := 0, 0
	for i := range 6000 {
		alphabet, minLen, spread := colliding, 1, 7
		if i%3 == 0 {
			alphabet, minLen, spread = tokens, 4, 12
		}
		n := rng.IntN(40)
		values := make([]string, n)
		for j := range values {
			values[j] = randString(rng, alphabet, minLen+rng.IntN(spread))
		}
		split := rng.IntN(n + 1)
		texts := make([]string, 4)
		for j := range texts {
			texts[j] = randText(rng, alphabet, values)
		}
		if equivCase(t, values[:split], values[split:], texts) {
			found++
		} else {
			sequential++
		}
	}
	// Both paths must actually have been compared, or this proves little.
	if found < 500 || sequential < 500 {
		t.Fatalf("searched first %d times, plain sequential %d; want both >= 500", found, sequential)
	}
}

// TestRedactorFindsEveryPattern pins a case the random sets rarely draw:
// two patterns start at the same place, the longer one is later destroyed
// by a third that overlaps its tail, and the shorter one must still be
// masked. A search that recorded only the first pattern found at each
// position would leave "abcd" in the clear.
func TestRedactorFindsEveryPattern(t *testing.T) {
	secrets := []string{"exyzwv", "abcde", "abcd"}
	// Padding puts the list on the search-first path.
	for i := range seqMax {
		secrets = append(secrets, "pad-secret-"+string(rune('a'+i)))
	}
	if !equivCase(t, secrets, nil, []string{"abcdexyzwv", "<abcdexyzwv abcdex>"}) {
		t.Fatal("the list did not reach the search-first path")
	}
}

// FuzzRedactorMatchesOracle feeds arbitrary secret lists and texts to the
// same comparison. Lines of secrets starting with '!' are registered as
// personal values.
func FuzzRedactorMatchesOracle(f *testing.F) {
	f.Add("abcd\nbcde\n!Ada Lovelace\n!Ada", "xabcdex Ada Lovelace, Ada")
	f.Add("a/b c\na%2Fb+c", "a%2Fb+c a/b c")
	f.Add("ab*c\n!b***", "ab*c***")
	f.Fuzz(func(t *testing.T, list, text string) {
		var secrets, personal []string
		for _, line := range strings.Split(list, "\n") {
			if p, ok := strings.CutPrefix(line, "!"); ok {
				personal = append(personal, p)
			} else {
				secrets = append(secrets, line)
			}
		}
		equivCase(t, secrets, personal, []string{text, list + text})
	})
}
