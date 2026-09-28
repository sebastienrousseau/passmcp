// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"satellion.com/passmcp"
)

// PersonalDataTool is a tool whose input or output schema names fields that
// hold personal data.
type PersonalDataTool struct {
	Tool string `json:"tool"`
	// Fields are schema paths, prefixed with the side they are on:
	// "input.customer.email", "output.phone".
	Fields []string `json:"fields"`
}

// checkPersonalData names the tools whose schemas take or return personal
// data: e-mail addresses, phone numbers, names, postal addresses, dates of
// birth and national identifiers.
//
// It is an observation, never a verdict. A CRM tool that returns a
// customer's e-mail is doing its job; what a data protection officer needs
// is to know that it does, for the record of processing (GDPR Art. 30) and
// the DPIA (Art. 35). So every result is info: a tool is neither better
// nor worse for handling personal data, and the score does not move.
//
// It reads field names from the schemas the server published. It does not
// call a tool and does not look at a value, so it cannot tell a field that
// is always empty from one that is not — which is why it names fields and
// makes no claim about what flows through them.
func checkPersonalData(s *Session, tools []passmcp.Tool) []Finding {
	const title = "Tools whose schemas name personal data"
	var hits []PersonalDataTool
	for _, t := range tools {
		fields := append(schemaPersonalFields("input", t.InputSchema), schemaPersonalFields("output", t.OutputSchema)...)
		if len(fields) > 0 {
			hits = append(hits, PersonalDataTool{Tool: t.Name, Fields: fields})
		}
	}
	s.PersonalData = hits
	if len(hits) == 0 {
		return []Finding{s.check("catalog.personal_data", title).info("no tool's input or output schema names a personal-data field")}
	}
	out := make([]Finding, 0, len(hits))
	for _, h := range hits {
		detail := fmt.Sprintf("%s: %s", truncate(h.Tool, 80), truncate(strings.Join(h.Fields, ", "), 300))
		out = append(out, s.check("catalog.personal_data", title).info(detail))
	}
	return out
}

// personalSchemaDepth bounds the walk: a schema is server-controlled, and a
// recursive or pathological one must not make the catalogue phase slow.
const personalSchemaDepth = 8

// schemaPersonalFields walks a JSON Schema's properties and returns the
// paths of those that name personal data.
func schemaPersonalFields(side string, raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var schema map[string]any
	if json.Unmarshal(raw, &schema) != nil {
		return nil
	}
	seen := map[string]bool{}
	walkPersonal(schema, side, 0, seen)
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func walkPersonal(node map[string]any, path string, depth int, seen map[string]bool) {
	if depth > personalSchemaDepth || len(seen) > 64 {
		return
	}
	if props, ok := node["properties"].(map[string]any); ok {
		walkProperties(props, path, depth, seen)
	}
	if items, ok := node["items"].(map[string]any); ok {
		walkPersonal(items, path+"[]", depth+1, seen)
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		list, _ := node[k].([]any)
		for _, v := range list {
			if sub, ok := v.(map[string]any); ok {
				walkPersonal(sub, path, depth+1, seen)
			}
		}
	}
}

// walkProperties records the personal fields among a schema's properties
// and descends into each.
func walkProperties(props map[string]any, path string, depth int, seen map[string]bool) {
	for name, v := range props {
		child, _ := v.(map[string]any)
		desc, _ := child["description"].(string)
		if personalField(name, desc) {
			seen[truncate(path+"."+name, 120)] = true
		}
		if child != nil {
			walkPersonal(child, path+"."+name, depth+1, seen)
		}
	}
}

// personalKeys are normalised field names (lower case, no separators) that
// hold personal data on their own.
var personalKeys = map[string]bool{
	"email": true, "emailaddress": true, "mail": true,
	"phone": true, "phonenumber": true, "telephone": true, "mobile": true, "mobilenumber": true, "cellphone": true, "msisdn": true, "tel": true,
	"firstname": true, "lastname": true, "fullname": true, "givenname": true, "familyname": true, "surname": true, "middlename": true, "forename": true, "displayname": true, "personname": true, "customername": true, "contactname": true, "patientname": true, "employeename": true,
	"address": true, "streetaddress": true, "postaladdress": true, "homeaddress": true, "mailingaddress": true, "billingaddress": true, "shippingaddress": true, "street": true, "postcode": true, "postalcode": true, "zipcode": true,
	"dob": true, "dateofbirth": true, "birthdate": true, "birthday": true,
	"ssn": true, "socialsecuritynumber": true, "nationalid": true, "nationalidentifier": true, "nationalinsurancenumber": true, "nino": true, "passport": true, "passportnumber": true, "taxid": true, "idnumber": true,
}

// personalDescription is what makes a bare "name" personal: a field called
// name is more often a repository or a file than a person.
var personalDescription = regexp.MustCompile(`(?i)\b(person|people|customer|user|contact|patient|employee|member|your)\b`)

// personalField reports whether a field name, with its description, names
// personal data.
func personalField(name, description string) bool {
	k := strings.NewReplacer("_", "", "-", "", " ", "", ".", "").Replace(strings.ToLower(name))
	if k == "name" {
		return personalDescription.MatchString(description)
	}
	if strings.Contains(k, "ipaddress") || strings.Contains(k, "macaddress") {
		return false
	}
	if personalKeys[k] {
		return true
	}
	return strings.Contains(k, "email") || strings.Contains(k, "phonenumber")
}
