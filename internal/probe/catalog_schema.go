// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"satellion.com/passmcp"
)

// schemaTally collects the issues in a catalogue's schemas by level, each
// labelled with the tool, the field and the JSON pointer it came from.
type schemaTally struct {
	byLevel  [schemaInvalid + 1][]string
	examined int
}

// add examines one schema a tool declares. An absent schema is not
// examined: catalog.tools.input_schema reports a missing inputSchema, and
// outputSchema is optional.
func (st *schemaTally) add(tool, field string, raw json.RawMessage) {
	if b := bytes.TrimSpace(raw); len(b) == 0 || string(b) == "null" {
		return
	}
	st.examined++
	for _, is := range checkSchemaDoc(raw) {
		st.byLevel[is.Level] = append(st.byLevel[is.Level],
			fmt.Sprintf("%s %s#%s: %s", truncate(tool, 64), field, truncate(is.Pointer, 80), is.Msg))
	}
}

// checkSchemaValidity judges whether every tool's inputSchema and
// outputSchema is structurally valid JSON Schema 2020-12, as far as a
// client depends on one. The schemas were read from the tools/list
// response, and the finding cites that request.
func checkSchemaValidity(s *Session, tools []passmcp.Tool) Finding {
	c := s.check("catalog.tools.schema_valid", "Tool schemas are structurally valid JSON Schema")
	if s.toolsListRef != "" {
		c.ev(s.toolsListRef)
	}
	var st schemaTally
	for _, t := range tools {
		st.add(t.Name, "inputSchema", t.InputSchema)
		st.add(t.Name, "outputSchema", t.OutputSchema)
	}
	// Tool names, keywords and pointers are the server's text.
	red := s.Opts.Recorder.Redactor.String
	switch {
	case st.examined == 0:
		return c.skip("no tool declares an inputSchema or outputSchema to examine")
	case len(st.byLevel[schemaInvalid]) > 0:
		return c.fail(Major, red(summariseIssues(st.byLevel[schemaInvalid])),
			"fix each schema at the pointer named: a client that cannot read a schema cannot build or check arguments for the tool, and many refuse to offer it")
	case len(st.byLevel[schemaWarn]) > 0:
		return c.warn(red(summariseIssues(st.byLevel[schemaWarn])),
			"declare every required property under properties, and use 2020-12 forms, so every client reads the schema the same way")
	}
	detail := fmt.Sprintf("%s across %s are structurally valid", plural(st.examined, "schema"), plural(len(tools), "tool"))
	switch {
	case len(st.byLevel[schemaInfo]) > 0:
		return c.info(red(detail + "; noted: " + summariseIssues(st.byLevel[schemaInfo])))
	case s.toolsListRef == "":
		return c.info(detail + " (no listing request to cite)")
	}
	return c.pass(detail)
}

// summariseIssues lists the first few issues and counts the rest.
func summariseIssues(issues []string) string {
	const shown = 5
	if len(issues) <= shown {
		return strings.Join(issues, "; ")
	}
	return strings.Join(issues[:shown], "; ") + fmt.Sprintf(" (+%d more)", len(issues)-shown)
}
