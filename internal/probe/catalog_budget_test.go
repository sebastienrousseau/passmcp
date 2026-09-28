// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// catalogue builds the minimum a catalogue check reads. The existing
// `session` helper in poison_probe_test.go takes a slice; this takes
// variadic tools, which is what every case here wants.
func catalogue(tools ...passmcp.Tool) *Session {
	return &Session{Opts: Options{Recorder: telemetry.New()}, Tools: tools}
}

func only(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	return fs[0]
}

// tool builds a tool whose JSON weighs roughly the requested number of bytes,
// by padding the description. Padding the description rather than the schema
// keeps the schema valid for the ambiguity check.
func tool(name string, weight int, schema string) passmcp.Tool {
	if schema == "" {
		schema = `{"type":"object"}`
	}
	t := passmcp.Tool{Name: name, Description: "d", InputSchema: json.RawMessage(schema)}
	for toolWeight(t) < weight {
		t.Description += strings.Repeat("x", 64)
	}
	return t
}

func TestCatalogueBudgetPassesASmallCatalogue(t *testing.T) {
	s := catalogue(tool("a", 200, ""), tool("b", 200, ""))
	f := only(t, checkCatalogueBudget(s))
	if f.Status != Pass {
		t.Errorf("a two-tool catalogue was %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"2 tools", TokenRule} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail is missing %q: %s", want, f.Detail)
		}
	}
}

// TestCatalogueBudgetWarnsOverTheBudget and fails far over it. The two
// thresholds exist so the check can gate without being a nuisance, and a
// single threshold would have to be one or the other.
func TestCatalogueBudgetThresholds(t *testing.T) {
	over := func(tokens int) *Session {
		// One tool per 2,000 tokens, so the catalogue is large because it
		// has many tools rather than one absurd one.
		var tools []passmcp.Tool
		for i := 0; i*2000 < tokens; i++ {
			tools = append(tools, tool(fmt.Sprintf("t%d", i), 8000, ""))
		}
		return catalogue(tools...)
	}

	warn := only(t, checkCatalogueBudget(over(CatalogueTokenBudget+4000)))
	if warn.Status != Warn {
		t.Errorf("a catalogue over the budget was %s: %s", warn.Status, warn.Detail)
	}
	if !strings.Contains(warn.Detail, fmt.Sprint(CatalogueTokenBudget)) {
		t.Errorf("the warning does not say what the budget is: %s", warn.Detail)
	}

	fail := only(t, checkCatalogueBudget(over(CatalogueTokenHard+8000)))
	if fail.Status != Fail {
		t.Errorf("a catalogue far over the budget was %s: %s", fail.Status, fail.Detail)
	}
	if fail.Severity != Major {
		t.Errorf("severity = %s", fail.Severity)
	}
}

// TestCatalogueBudgetNamesTheLargestTools: "it is too big" is not
// actionable; "these three are most of it" is.
func TestCatalogueBudgetNamesTheLargestTools(t *testing.T) {
	s := catalogue(tool("small", 200, ""), tool("enormous", 3000, ""), tool("medium", 900, ""))
	f := only(t, checkCatalogueBudget(s))
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "enormous") {
		t.Errorf("the largest tool is not named: %v", f.Evidence)
	}
	if i, j := strings.Index(ev, "enormous"), strings.Index(ev, "medium"); i > j && j >= 0 {
		t.Errorf("tools are not ordered by weight: %s", ev)
	}
}

// TestOneFatToolIsFoundInsideASmallCatalogue. A server can be under budget
// overall and still have one tool that is really several.
func TestOneFatToolIsFoundInsideASmallCatalogue(t *testing.T) {
	s := catalogue(tool("tiny", 100, ""), tool("sprawling", (ToolTokenBudget+200)*4, ""))
	f := only(t, checkCatalogueBudget(s))
	if f.Status != Warn {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "sprawling") {
		t.Errorf("the oversized tool is not named: %s", f.Detail)
	}
}

func TestCatalogueBudgetSaysNothingAboutAnEmptyCatalogue(t *testing.T) {
	if got := checkCatalogueBudget(catalogue()); got != nil {
		t.Errorf("an empty catalogue produced %d finding(s)", len(got))
	}
}

// --- parameter ambiguity ---------------------------------------------------

const describedSchema = `{"type":"object","properties":{
  "id":{"type":"string","description":"The account id from list_accounts.","pattern":"^a-[0-9]+$"}
},"required":["id"]}`

func TestAmbiguityPassesADescribedConstrainedParameter(t *testing.T) {
	f := only(t, checkParameterAmbiguity(catalogue(tool("look", 0, describedSchema))))
	if f.Status != Pass {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
}

// TestUndescribedRequiredParameterFails is the acute case: the model must
// supply the value and has been told only its type, so it guesses — and the
// call is well-formed, so nothing else in the run notices.
func TestUndescribedRequiredParameterFails(t *testing.T) {
	schema := `{"type":"object","properties":{"arg1":{"type":"string"}},"required":["arg1"]}`
	f := only(t, checkParameterAmbiguity(catalogue(tool("look", 0, schema))))
	if f.Status != Fail {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	if f.Severity != Major {
		t.Errorf("severity = %s", f.Severity)
	}
	if !strings.Contains(f.Detail, "look.arg1") {
		t.Errorf("the parameter is not named: %s", f.Detail)
	}
}

// An optional undescribed parameter is a warning, not a failure: the model
// can simply not supply it.
func TestUndescribedOptionalParameterWarns(t *testing.T) {
	schema := `{"type":"object","properties":{
	  "id":{"type":"string","description":"The account id.","format":"uuid"},
	  "verbose":{"type":"boolean"}},"required":["id"]}`
	f := only(t, checkParameterAmbiguity(catalogue(tool("look", 0, schema))))
	if f.Status != Warn {
		t.Fatalf("status = %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "look.verbose") {
		t.Errorf("the parameter is not named: %s", f.Detail)
	}
}

// Described but unconstrained is an observation rather than a defect: the
// prose may be enough, and saying otherwise would make the check noise.
func TestDescribedButUnconstrainedIsInfo(t *testing.T) {
	schema := `{"type":"object","properties":{"q":{"type":"string","description":"What to search for."}},"required":["q"]}`
	f := only(t, checkParameterAmbiguity(catalogue(tool("search", 0, schema))))
	if f.Status != Info {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
}

func TestAmbiguitySkipsAToolWithNoParameters(t *testing.T) {
	f := only(t, checkParameterAmbiguity(catalogue(tool("ping", 0, `{"type":"object"}`))))
	if f.Status != Skip {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
}

// A schema that is not JSON, or not an object schema, is already reported by
// catalog.tools.input_schema. This check must not report it twice, and must
// not crash on it.
func TestAmbiguityIgnoresAnUnreadableSchema(t *testing.T) {
	s := catalogue(
		passmcp.Tool{Name: "broken", InputSchema: json.RawMessage(`not json`)},
		tool("fine", 0, describedSchema),
	)
	f := only(t, checkParameterAmbiguity(s))
	if f.Status != Pass {
		t.Errorf("status = %s: %s", f.Status, f.Detail)
	}
	if strings.Contains(f.Detail, "broken") {
		t.Errorf("an unreadable schema was reported here as well: %s", f.Detail)
	}
}

func TestApproxTokensNamesItsRule(t *testing.T) {
	if approxTokens(0) != 0 {
		t.Error("empty is not free")
	}
	if got := approxTokens(4); got != 1 {
		t.Errorf("4 chars = %d tokens", got)
	}
	// Rounds up: three characters still cost a token.
	if got := approxTokens(3); got != 1 {
		t.Errorf("3 chars = %d tokens", got)
	}
	if TokenRule == "" {
		t.Error("the rule is not named, so a reader cannot reproduce the number")
	}
}

// TestHumanBytesScales: the figure appears in every budget finding, and a
// catalogue measured in megabytes is exactly the case worth reading clearly.
func TestHumanBytesScales(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{
		{0, "0 B"}, {512, "512 B"}, {2048, "2.0 KB"}, {3 << 20, "3.0 MB"},
	} {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestToolWeightFallsBackWhenAToolWillNotMarshal.
//
// A tool carrying invalid raw JSON cannot be marshalled, and returning zero
// for it would understate the catalogue — the one direction a budget must
// never err in, because it would let the largest tool be the invisible one.
func TestToolWeightFallsBackWhenAToolWillNotMarshal(t *testing.T) {
	broken := passmcp.Tool{
		Name:        "broken",
		Description: strings.Repeat("y", 100),
		InputSchema: json.RawMessage(`{invalid`),
	}
	w := toolWeight(broken)
	if w < 100 {
		t.Errorf("weight %d understates a tool with a 100-character description", w)
	}
	// And it still counts towards the catalogue rather than vanishing.
	f := only(t, checkCatalogueBudget(catalogue(broken)))
	if f.Status == Skip {
		t.Error("an unmarshalable tool removed the catalogue from the budget")
	}
}
