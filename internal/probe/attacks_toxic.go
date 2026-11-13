// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"satellion.com/passmcp"
)

// --- ATK-02: capabilities that combine into an exfiltration path ---------------

// splitName breaks a tool name into lower-case words at separators and
// camel-case boundaries: read_file, readFile and read-file all give
// [read file].
func splitName(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && len(cur) > 0 && unicode.IsLower(cur[len(cur)-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// privateNouns are what a tool reads when what it reads is the user's or the
// host's rather than the public web's.
var privateNouns = map[string]bool{
	"file": true, "files": true, "dir": true, "directory": true, "folder": true, "path": true,
	"document": true, "documents": true, "db": true, "database": true, "sql": true, "table": true,
	"record": true, "records": true, "email": true, "emails": true, "inbox": true, "mail": true,
	"messages": true, "contact": true, "contacts": true, "calendar": true, "note": true, "notes": true,
	"secret": true, "secrets": true, "credential": true, "credentials": true, "env": true,
	"clipboard": true, "history": true, "customer": true, "customers": true, "account": true,
	"accounts": true, "repo": true, "repository": true, "issue": true, "issues": true,
}

// staticArtefactNouns are generic container words that refer to user files on
// an open tool, yet routinely name shipped fixtures on a closed-world library
// server (e.g. list_corpus_files, get_example_document). Personal, account
// and credential nouns (inbox, secrets, customer, database) never qualify.
var staticArtefactNouns = map[string]bool{
	"file": true, "files": true, "document": true, "documents": true, "record": true, "records": true,
}

// fixtureQualifiers mark a closed-world static-artefact tool as reading
// bundled reference material rather than arbitrary user data on the host.
var fixtureQualifiers = map[string]bool{
	"corpus": true, "example": true, "examples": true, "sample": true, "samples": true,
	"fixture": true, "fixtures": true, "template": true, "templates": true, "bundled": true,
}

var fixtureDescRe = regexp.MustCompile(`(?i)\b(corpus|examples?|samples?|fixtures?|templates?|bundled)\b`)

var readVerbs = map[string]bool{
	"read": true, "get": true, "list": true, "search": true, "query": true, "load": true,
	"open": true, "view": true, "cat": true, "find": true, "lookup": true, "fetch": true, "show": true,
}

// sendVerbs are what a tool does when it moves data somewhere the user does
// not control.
var sendVerbs = map[string]bool{
	"send": true, "post": true, "publish": true, "upload": true, "notify": true, "share": true,
	"forward": true, "tweet": true, "webhook": true, "curl": true, "email": true, "mail": true,
}

var outboundNouns = map[string]bool{"url": true, "webhook": true, "http": true, "https": true}

var privateDescRe = regexp.MustCompile(`(?i)\b(reads?|returns?|lists?|retrieves?|searches|gets?|loads?)\b.{0,40}\b(local (files?|disk)|file ?system|files? on (disk|the machine)|private|personal data|confidential|credentials?|secrets?|database|inbox|e-?mails?|clipboard|home directory)\b`)

var outboundDescRe = regexp.MustCompile(`(?i)\b(sends?|posts?|publishes|uploads?|forwards?)\b.{0,40}\b(e-?mail|message|webhook|url|endpoint|server|channel|external|anyone|recipient)s?\b|\b(http requests? to (any|an arbitrary|the given)|arbitrary urls?|outbound requests?)\b`)

func readVerbAndNoun(words []string) string {
	verb, noun := false, ""
	for _, w := range words {
		verb = verb || readVerbs[w]
		if privateNouns[w] && noun == "" {
			noun = w
		}
	}
	if !verb {
		return ""
	}
	return noun
}

func isClosedWorld(a *passmcp.ToolAnnotations) bool {
	return a != nil && a.OpenWorldHint != nil && !*a.OpenWorldHint
}

func isBundledFixture(t passmcp.Tool, words []string, noun string) bool {
	if !staticArtefactNouns[noun] || !isClosedWorld(t.Annotations) {
		return false
	}
	for _, w := range words {
		if fixtureQualifiers[w] {
			return true
		}
	}
	return fixtureDescRe.MatchString(t.Description)
}

// privateReader returns why t reads local or private data, or nil when
// nothing says it does. The name or the description must say so; an
// annotation or a schema field only supports a reading, never makes one.
// A closed-world tool that reads bundled fixtures (corpus, example, sample,
// fixture, template) on a generic artefact noun with no host-path parameter
// and no local-disk description is excluded.
func privateReader(t passmcp.Tool) []string {
	words := splitName(t.Name)
	noun := readVerbAndNoun(words)
	descMatch := privateDescRe.FindString(t.Description)
	pathField := schemaField(t.InputSchema, "path", "file", "filepath", "filename", "directory", "dir", "sql")
	if descMatch == "" && pathField == "" && isBundledFixture(t, words, noun) {
		return nil
	}
	var why []string
	if noun != "" {
		why = append(why, fmt.Sprintf("name %q reads %s", t.Name, noun))
	}
	if descMatch != "" {
		why = append(why, fmt.Sprintf("description says it %q", truncate(descMatch, 60)))
	}
	if len(why) == 0 {
		return nil
	}
	if pathField != "" {
		why = append(why, "inputSchema takes "+pathField)
	}
	if isClosedWorld(t.Annotations) {
		why = append(why, "openWorldHint: false")
	}
	return why
}

func hasSendWord(words []string) bool {
	for i, w := range words {
		if sendVerbs[w] || (outboundNouns[w] && i > 0) {
			return true
		}
	}
	return false
}

func isOpenWorldMutator(a *passmcp.ToolAnnotations) bool {
	if a == nil || a.OpenWorldHint == nil || !*a.OpenWorldHint {
		return false
	}
	return a.ReadOnlyHint == nil || !*a.ReadOnlyHint
}

// outboundSender returns why t sends data outside the user's control, or
// nil when nothing says it does. An explicit openWorldHint on a tool that
// is not read-only is a statement the server made about itself, so it is
// enough on its own.
func outboundSender(t passmcp.Tool) []string {
	var why []string
	if hasSendWord(splitName(t.Name)) {
		why = append(why, fmt.Sprintf("name %q sends data out", t.Name))
	}
	if m := outboundDescRe.FindString(t.Description); m != "" {
		why = append(why, fmt.Sprintf("description says it %q", truncate(m, 60)))
	}
	if isOpenWorldMutator(t.Annotations) {
		why = append(why, "openWorldHint: true and not read-only")
	}
	return why
}

// schemaField returns the first property of an object schema whose name is
// one of names, or "".
func schemaField(raw json.RawMessage, names ...string) string {
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	props := make([]string, 0, len(doc.Properties))
	for p := range doc.Properties {
		props = append(props, p)
	}
	sort.Strings(props)
	for _, p := range props {
		for _, n := range names {
			if strings.EqualFold(p, n) {
				return p
			}
		}
	}
	return ""
}

// capability is one tool and why it was read as holding a capability.
type capability struct {
	tool string
	why  []string
}

// checkToxicCombination reports a server that exposes both halves of an
// exfiltration: a tool that reads what is private, and another that sends
// data out. Neither is a defect alone, and together they are exactly what a
// prompt injection needs, whoever authored the catalogue.
func checkToxicCombination(s *Session) Finding {
	c := s.check("catalog.toxic_combination", "No tool pair reads private data and sends it out")
	var readers, senders []capability
	for _, t := range s.Tools {
		if why := privateReader(t); why != nil {
			readers = append(readers, capability{t.Name, why})
		}
		if why := outboundSender(t); why != nil {
			senders = append(senders, capability{t.Name, why})
		}
	}
	var pairs []string
	for _, r := range readers {
		for _, w := range senders {
			if r.tool == w.tool {
				continue
			}
			pairs = append(pairs, fmt.Sprintf("%s (reads: %s) with %s (sends: %s)",
				r.tool, strings.Join(r.why, "; "), w.tool, strings.Join(w.why, "; ")))
		}
	}
	if len(pairs) == 0 {
		return c.pass(fmt.Sprintf("%d tools: none reads local or private data beside another that sends data out", len(s.Tools)))
	}
	shown := min(len(pairs), 3)
	detail := fmt.Sprintf("%d pair(s): %s", len(pairs), strings.Join(pairs[:shown], "; "))
	if len(pairs) > shown {
		detail += fmt.Sprintf("; and %d more", len(pairs)-shown)
	}
	return c.warn(s.Opts.Recorder.Redactor.String(detail),
		"split the reading and the sending across servers an operator approves separately, or require confirmation for the sending tool: an agent that can do both can be told by any text it reads to send what it read")
}
