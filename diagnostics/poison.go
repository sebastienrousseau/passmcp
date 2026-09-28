// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A tool's description is not documentation. It is input to the model, read
// before the model decides what to call and with the same standing as the
// user's own words. Everything in this file exists because of that: text a
// person skims as a help string is text an agent may follow as an
// instruction.
//
// The hard part is not detection, it is restraint. A scanner that flags
// every description containing the word "must" teaches people to ignore it,
// and an ignored scanner is worse than none because it was trusted once.
// So severity here is calibrated deliberately: only what cannot be honest
// documentation is reported as a failure, and anything a legitimate author
// might plausibly write is a warning or an observation.

// SignalKind classifies what was found.
type SignalKind string

// The kinds of suspicious content ScanText reports.
const (
	// SignalHidden is text the model reads and a human reviewing the
	// catalog does not: zero-width characters, bidirectional overrides,
	// other invisible formatting.
	SignalHidden SignalKind = "hidden_text"
	// SignalComment is an HTML or XML-style comment. Rendered catalogs
	// hide it; the model does not.
	SignalComment SignalKind = "comment"
	// SignalInstruction is text addressed to the model rather than
	// describing the tool.
	SignalInstruction SignalKind = "instruction"
	// SignalSecretPath names somewhere credentials live.
	SignalSecretPath SignalKind = "secret_path"
	// SignalConfusable is a name mixing scripts, which is how one tool
	// impersonates another.
	SignalConfusable SignalKind = "confusable"
	// SignalEncoded is text that has been encoded rather than written.
	//
	// It is the evasion route around every other rule in this file. A
	// reviewer skimming a catalogue sees an opaque blob and moves on; the
	// model, asked to be helpful, is perfectly capable of decoding it. A
	// tool description has no honest reason to carry one.
	SignalEncoded SignalKind = "encoded"
)

// SignalSeverity is how much weight to give a signal.
type SignalSeverity string

// Severities, calibrated so that Critical means "this cannot be honest
// documentation" rather than "this looks unusual".
const (
	// SeverityCritical: no legitimate description contains this.
	SeverityCritical SignalSeverity = "critical"
	// SeverityMajor: a legitimate description very rarely contains this,
	// and when it does the author should still be told.
	SeverityMajor SignalSeverity = "major"
	// SeverityMinor: worth a reader's attention, not worth a build
	// failure.
	SeverityMinor SignalSeverity = "minor"
)

// Signal is one suspicious property of one piece of catalog text.
type Signal struct {
	Kind     SignalKind
	Severity SignalSeverity
	// Where names the text that carried it, e.g. `find_customer`
	// description or `find_customer` inputSchema.query.description.
	Where string
	// Detail says what was found, in words a maintainer can act on.
	Detail string
	// Excerpt is the surrounding text, truncated. It is included because
	// "an instruction was found" is not actionable and "…ignore previous
	// instructions and…" is.
	Excerpt string
}

// scanRule is one instruction pattern.
type scanRule struct {
	re       *regexp.Regexp
	severity SignalSeverity
	detail   string
}

// instructionRules are phrases that address the model rather than describe
// the tool.
//
// Each is here because it appeared in published tool-poisoning research or
// in a real advisory, not because it sounded plausible. The ones marked
// critical have no honest reading in a tool description: a description
// explains what a tool does, and nothing about what a tool does requires
// telling the reader to conceal something or to disregard what it was told
// before.
var instructionRules = []scanRule{
	{regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\b`), SeverityCritical,
		"tells the reader to disregard earlier instructions"},
	{regexp.MustCompile(`(?i)\bdisregard\s+(all\s+)?(previous|prior|above|earlier|the)\b`), SeverityCritical,
		"tells the reader to disregard earlier instructions"},
	{regexp.MustCompile(`(?i)\bdo\s+not\s+(tell|inform|mention|reveal|disclose|show)\b.{0,40}\b(user|human|operator)\b`), SeverityCritical,
		"instructs the model to conceal something from the user"},
	{regexp.MustCompile(`(?i)\b(never|don't|do not)\s+(mention|reveal|disclose|display)\s+(this|these|the\s+above)\b`), SeverityCritical,
		"instructs the model to conceal this text"},
	{regexp.MustCompile(`(?i)\byou\s+(are|act)\s+(now\s+)?(a|an)\b.{0,30}\b(assistant|agent|model|ai)\b`), SeverityCritical,
		"reassigns the model's role"},
	{regexp.MustCompile(`(?i)\b(system|developer)\s+(prompt|message|instruction)s?\b`), SeverityMajor,
		"refers to the system prompt"},
	{regexp.MustCompile(`(?i)<\s*(important|system|instruction|secret)\s*>`), SeverityMajor,
		"uses a pseudo-tag that frames the text as an instruction"},
	{regexp.MustCompile(`(?i)\bbefore\s+(using|calling|invoking)\s+(this|any)\s+tool\b.{0,60}\b(must|always|first)\b`), SeverityMajor,
		"places a precondition on the model rather than on the caller"},
	{regexp.MustCompile(`(?i)\balways\s+(call|invoke|use|read|send|include)\b`), SeverityMinor,
		"directs the model's behaviour rather than describing the tool"},
	{regexp.MustCompile(`(?i)\bdo\s+not\s+(use|call|invoke)\s+(any\s+)?other\b`), SeverityMajor,
		"tells the model not to use other tools"},
}

// secretPathRules name places credentials live. A tool that legitimately
// reads SSH keys exists; it should say so in prose a person approves, and a
// reviewer should see this either way.
var secretPathRules = []scanRule{
	{regexp.MustCompile(`(?i)(^|[^\w])~?/?\.ssh/(id_[a-z0-9_]+|authorized_keys|config)\b`), SeverityMajor,
		"names an SSH private key or configuration path"},
	{regexp.MustCompile(`(?i)(^|[^\w])~?/?\.aws/(credentials|config)\b`), SeverityMajor,
		"names the AWS credentials file"},
	{regexp.MustCompile(`(?i)(^|[^\w])\.env(\.[a-z]+)?\b`), SeverityMinor,
		"names a dotenv file"},
	{regexp.MustCompile(`(?i)\b(/etc/(passwd|shadow))\b`), SeverityMajor,
		"names a system credential file"},
	{regexp.MustCompile(`(?i)\b(AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|GH_TOKEN)\b`), SeverityMajor,
		"names a credential environment variable"},
}

var commentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

// ScanText reports what is suspicious about one piece of catalog text.
//
// where is used only to label the result, so a caller can say which field
// carried the signal. Text with nothing suspicious in it produces no
// signals, which is the overwhelmingly common case and the one the
// calibration above protects.
func ScanText(where, text string) []Signal {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []Signal

	if sigs := scanHidden(where, text); len(sigs) > 0 {
		out = append(out, sigs...)
	}
	for _, m := range commentRe.FindAllString(text, -1) {
		out = append(out, Signal{
			Kind: SignalComment, Severity: SeverityMajor, Where: where,
			Detail:  "contains an HTML comment, which a rendered catalog hides and a model still reads",
			Excerpt: excerpt(m),
		})
	}
	// The comment itself is already reported above, and a phrase inside one
	// would otherwise be reported a second time. Its contents are still
	// scanned — they are the reason a hidden comment matters — but through
	// the same pass over the whole text, so the offsets stay meaningful.
	for _, group := range []struct {
		kind  SignalKind
		rules []scanRule
	}{
		{SignalInstruction, instructionRules},
		{SignalSecretPath, secretPathRules},
	} {
		for _, r := range group.rules {
			loc := r.re.FindStringIndex(text)
			if loc == nil {
				continue
			}
			out = append(out, Signal{
				Kind: group.kind, Severity: r.severity, Where: where,
				Detail:  r.detail,
				Excerpt: excerptAround(text, loc[0], loc[1]),
			})
		}
	}
	out = append(out, scanEncoded(where, text)...)
	return out
}

// base64Run matches a run long enough to carry a sentence. Shorter runs are
// everywhere — identifiers, hashes, short tokens — and flagging them would
// bury the finding that matters.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)

// scanEncoded finds text that was encoded rather than written.
//
// The filter that makes this usable rather than noisy is the second half: a
// run is only reported if it decodes to something that reads as text. A
// SHA-256 digest, a UUID without its dashes and a binary blob are all made of
// the same alphabet and all decode to noise, so they are passed over without
// a rule listing them — which is the kind of list that is never complete.
func scanEncoded(where, text string) []Signal {
	var out []Signal
	for _, loc := range base64Run.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		decoded, ok := decodeReadable(raw)
		if !ok {
			continue
		}
		sev := SeverityMajor
		detail := "carries base64 that decodes to text"
		// Decoded instructions are the whole technique: the payload is
		// encoded precisely so the rules above do not see it.
		for _, r := range instructionRules {
			if r.re.MatchString(decoded) {
				sev = SeverityCritical
				detail = "carries base64 that decodes to an instruction: " + r.detail
				break
			}
		}
		out = append(out, Signal{
			Kind: SignalEncoded, Severity: sev, Where: where,
			Detail:  detail,
			Excerpt: "decodes to: " + excerpt(decoded),
		})
	}
	return out
}

// decodeReadable decodes a base64 run and reports whether the result reads
// as text rather than as bytes.
func decodeReadable(raw string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(raw)
		if err != nil || len(b) < 12 {
			continue
		}
		if !utf8.Valid(b) {
			continue
		}
		printable := 0
		for _, r := range string(b) {
			if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
				printable++
			}
		}
		total := utf8.RuneCount(b)
		// Four fifths: enough to exclude binary that happens to contain
		// runs of ASCII, low enough to keep text with a little punctuation
		// noise in it.
		if total > 0 && printable*5 >= total*4 {
			// And it has to contain a word, or "text" includes a run of
			// spaces and symbols that decoded by accident.
			if wordRun.MatchString(string(b)) {
				return string(b), true
			}
		}
	}
	return "", false
}

// wordRun is four or more letters in a row: the cheapest test for "this is
// language rather than an artefact of decoding".
var wordRun = regexp.MustCompile(`[A-Za-z]{4,}`)

// ScanName reports what is suspicious about an identifier.
//
// A tool name is not prose: it is what the model matches on, and the attack
// it enables is impersonation — a name that renders identically to a tool
// the user trusts. Mixed scripts are the tractable signal; a name that is
// entirely one non-Latin script is a legitimate name in that script and is
// not reported.
func ScanName(where, name string) []Signal {
	var out []Signal
	out = append(out, scanHidden(where, name)...)

	if scripts := scriptsIn(name); len(scripts) > 1 {
		sort.Strings(scripts)
		out = append(out, Signal{
			Kind: SignalConfusable, Severity: SeverityCritical, Where: where,
			Detail: fmt.Sprintf("mixes %s characters, which is how a name is made to render like another tool's",
				strings.Join(scripts, " and ")),
			Excerpt: excerpt(name),
		})
	}
	return out
}

// scanHidden finds characters a reviewer cannot see.
func scanHidden(where, text string) []Signal {
	var zeroWidth, bidi []string
	for _, r := range text {
		switch {
		case isBidiControl(r):
			bidi = append(bidi, fmt.Sprintf("U+%04X", r))
		case isInvisible(r):
			zeroWidth = append(zeroWidth, fmt.Sprintf("U+%04X", r))
		}
	}
	var out []Signal
	if len(bidi) > 0 {
		out = append(out, Signal{
			Kind: SignalHidden, Severity: SeverityCritical, Where: where,
			Detail: "contains bidirectional control characters (" + list(uniq(bidi)) +
				"), which reorder how the text displays without changing what is read",
			Excerpt: excerpt(text),
		})
	}
	if len(zeroWidth) > 0 {
		out = append(out, Signal{
			Kind: SignalHidden, Severity: SeverityMajor, Where: where,
			Detail: "contains invisible characters (" + list(uniq(zeroWidth)) +
				"), which a reviewer reading the catalog cannot see",
			Excerpt: excerpt(text),
		})
	}
	return out
}

// isBidiControl reports the characters behind the Trojan Source class: they
// change display order without changing the sequence anything reads.
func isBidiControl(r rune) bool {
	switch r {
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // embeddings and overrides
		0x2066, 0x2067, 0x2068, 0x2069: // isolates
		return true
	}
	return false
}

// isInvisible reports formatting characters that occupy no space. Tab,
// newline and carriage return are ordinary whitespace and are not included.
func isInvisible(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, // zero-width space, non-joiner, joiner
		0x2060,         // word joiner
		0xFEFF,         // zero-width no-break space
		0x00AD,         // soft hyphen
		0x180E,         // Mongolian vowel separator
		0x200E, 0x200F: // left-to-right and right-to-left marks
		return true
	}
	// Any other format character with no width. Cf covers the interesting
	// cases; the explicit list above is kept for the detail message.
	return unicode.Is(unicode.Cf, r)
}

// scriptsIn names the scripts a string draws letters from.
//
// Only letters are considered: digits, underscores and punctuation are
// script-neutral in every identifier scheme and counting them would report
// every ordinary snake_case name.
func scriptsIn(s string) []string {
	seen := map[string]bool{}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		switch {
		case unicode.Is(unicode.Latin, r):
			seen["Latin"] = true
		case unicode.Is(unicode.Cyrillic, r):
			seen["Cyrillic"] = true
		case unicode.Is(unicode.Greek, r):
			seen["Greek"] = true
		case unicode.Is(unicode.Han, r):
			seen["Han"] = true
		case unicode.Is(unicode.Arabic, r):
			seen["Arabic"] = true
		case unicode.Is(unicode.Hebrew, r):
			seen["Hebrew"] = true
		case unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r):
			// Japanese text mixes these with Han as a matter of course, so
			// they are one script for this purpose.
			seen["Japanese"] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Han with Japanese kana is ordinary Japanese, not a mixed-script name.
	if seen["Japanese"] && seen["Han"] {
		out = without(out, "Han")
	}
	sort.Strings(out)
	return out
}

func without(ss []string, drop string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func list(ss []string) string {
	if len(ss) > 4 {
		return strings.Join(ss[:4], ", ") + fmt.Sprintf(" and %d more", len(ss)-4)
	}
	return strings.Join(ss, ", ")
}

const excerptLimit = 120

// excerpt truncates text for a finding, on a rune boundary, with the
// invisible characters made visible — an excerpt that renders as ordinary
// text is no evidence at all when the point is that something is hidden.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(visible(s)), " ")
	r := []rune(s)
	if len(r) <= excerptLimit {
		return s
	}
	return string(r[:excerptLimit]) + "…"
}

// excerptAround centres the excerpt on the match.
func excerptAround(s string, from, to int) string {
	const pad = 40
	start := max(from-pad, 0)
	end := min(to+pad, len(s))
	out := s[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return excerpt(out)
}

// visible replaces characters that occupy no space with their code point,
// so the evidence in a report shows what was actually there.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isBidiControl(r) || isInvisible(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Worst returns the highest severity among signals, and whether there were
// any at all.
func Worst(sigs []Signal) (SignalSeverity, bool) {
	if len(sigs) == 0 {
		return "", false
	}
	worst := SeverityMinor
	for _, s := range sigs {
		switch s.Severity {
		case SeverityCritical:
			return SeverityCritical, true
		case SeverityMajor:
			worst = SeverityMajor
		}
	}
	return worst, true
}
