// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package pii names the field keys that hold personal data.
//
// Two parts of passmcp need the same answer. The catalog check in
// internal/probe reports a tool whose schema has a field such as
// patient_name as handling personal data; the recorder in
// internal/telemetry masks the value under such a key in a tool's result
// before it reaches a HAR, an NDJSON stream or a report. When each kept its
// own list they drifted, and the recorder left in the clear values the
// catalog had just flagged. This package is the one list and the one
// normalisation both use. It has no dependencies beyond the standard
// library, so either can import it.
package pii

import "strings"

// keys are normalised keys whose values are personal data on their own.
// "name" is here for the recorder, which masks it in results; the catalog
// check treats a bare "name" by its description before it consults this
// list, because a field called name is more often a file than a person.
var keys = map[string]bool{
	"email": true, "emailaddress": true, "mail": true,
	"phone": true, "phonenumber": true, "telephone": true, "mobile": true, "mobilenumber": true, "cellphone": true, "msisdn": true, "tel": true,
	"name": true, "firstname": true, "lastname": true, "fullname": true, "givenname": true, "familyname": true, "surname": true, "middlename": true, "forename": true, "displayname": true,
	"personname": true, "customername": true, "contactname": true, "patientname": true, "employeename": true,
	"address": true, "streetaddress": true, "postaladdress": true, "homeaddress": true, "mailingaddress": true, "billingaddress": true, "shippingaddress": true, "street": true,
	"postcode": true, "postalcode": true, "zipcode": true,
	"dob": true, "dateofbirth": true, "birthdate": true, "birthday": true,
	"ssn": true, "socialsecuritynumber": true, "nationalid": true, "nationalidentifier": true, "nationalinsurancenumber": true, "nino": true,
	"passport": true, "passportnumber": true, "taxid": true, "idnumber": true,
}

// separators are stripped from a key: patient_name, patient-name,
// "patient name" and patient.name are one key. A Replacer is safe for
// concurrent use, so it is built once.
var separators = strings.NewReplacer("_", "", "-", "", " ", "", ".", "")

// Normalise lower-cases key and strips its separators.
func Normalise(key string) string {
	return separators.Replace(strings.ToLower(key))
}

// Key reports whether a normalised key holds personal data on its own.
func Key(normalised string) bool {
	return keys[normalised]
}
