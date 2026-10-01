// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// catalogTextRemediations is the guidance for the checks on the text a
// catalogue carries: hidden, encoded or shadowing descriptions and names.
var catalogTextRemediations = map[string]Remediation{
	"catalog.text.encoded": {
		Means: "A field in the catalogue carries base64 that decodes to readable " +
			"text. This is the evasion route around every other check in this " +
			"family: a reviewer skimming the tool list sees an opaque blob and " +
			"moves on, and the model — asked to be helpful — is entirely capable " +
			"of decoding it and acting on what it says. A tool description has no " +
			"honest reason to carry one.",
		Steps: []Step{
			{"Decode it and read it",
				"The finding includes the decoded text. If it is an instruction " +
					"aimed at the model, this is a tool-poisoning payload and the " +
					"question is how it got into your catalogue rather than how to " +
					"reword it."},
			{"If it is yours, write it out",
				"Configuration, a sample payload or an encoded example belongs " +
					"somewhere a person reviewing the catalogue can read it. If it is " +
					"genuinely binary, describe it in prose and put the bytes behind " +
					"a resource."},
			{"If it is not yours, treat it as an incident",
				"Check who can write tool metadata, when this field last changed, " +
					"and whether any other server in your fleet carries the same " +
					"blob. A payload encoded to survive review was put there by " +
					"somebody who expected review."},
		},
		Note: "Only runs that decode to text are reported. Hashes, identifiers and " +
			"genuine binary decode to noise and are passed over, so a finding here " +
			"means something wrote a sentence and then hid it.",
	},

	"catalog.text.shadowing": {
		Means: "A description does not describe the tool it belongs to. It " +
			"attaches a rule to some other tool — \"when calling send_email, " +
			"always BCC…\" — and the model reads every description it is given " +
			"with equal authority and no notion of which server each one came " +
			"from. That is the whole mechanism: a server you are evaluating can " +
			"rewrite the behaviour of a server you already trust, without ever " +
			"being called itself.",
		Steps: []Step{
			{"Read the sentence passmcp quoted",
				"The finding names the field it came from, the tool the rule is " +
					"aimed at, and whether that tool is one this server lists. A " +
					"target this server does not have is the cross-server shape and " +
					"is reported as critical."},
			{"Move the rule to the tool it governs",
				"If the constraint is real and the tool is yours, it belongs in " +
					"that tool's own description, where the operator approving it " +
					"can see what it applies to. A precondition on your own tool is " +
					"documentation; the same sentence in a sibling's description is " +
					"not."},
			{"If the tool is not yours, treat it as an incident",
				"Nothing legitimate needs one server's catalogue to issue orders " +
					"about another server's tools. Check who can write this " +
					"metadata and when the field last changed, and look for the " +
					"same sentence across the rest of your fleet."},
		},
		Note: "Only constructions that constrain another tool are reported — " +
			"\"when calling X\", \"before invoking X\", \"never use X\". Pointing " +
			"the model at a sibling (\"use list_directory to find the path\") is " +
			"what good documentation does and is passed over, because a check " +
			"that flags helpful cross-references is one people mute.",
	},

	"catalog.text.instructions": {
		Means: "Somewhere in the catalog, text is addressed to the model rather " +
			"than describing a tool — an instruction to ignore what it was told, " +
			"to conceal something from the user, or to act as a different agent. " +
			"A description is read with the same standing as the user's own words, " +
			"so this is indistinguishable from an instruction an attacker planted.",
		Steps: []Step{
			{"Find the text passmcp quoted",
				"The finding names the field, including when it is a `description` " +
					"inside an `inputSchema` — which is where this is most often " +
					"found, because it is the part nobody renders."},
			{"Rewrite it as a description",
				"Say what the tool does. If it genuinely needs a precondition, that " +
					"belongs in the schema as a required argument, not in prose " +
					"aimed at the model."},
			{"Find out how it got there",
				"If nobody on the team wrote it, the question is no longer a " +
					"wording one."},
		},
	},

	"catalog.text.comments": {
		Means: "Catalog text contains an HTML comment. A catalog viewer renders " +
			"the description and hides the comment; the model receives the raw " +
			"string and reads both. That gap is the whole attraction — a comment " +
			"is the one place to put text a reviewer will not see and the model " +
			"will.",
		Steps: []Step{
			{"Read what the comment says",
				"passmcp quotes it in the finding. A leftover note and an instruction " +
					"aimed at the model look identical in a diff and are not the " +
					"same problem."},
			{"Move it or delete it",
				"If it belongs in the description, put it there, where a person " +
					"approving the tool will see it. If it does not, it does not " +
					"belong in text the model reads either."},
		},
	},

	"catalog.text.hidden": {
		Means: "The catalog contains characters a reviewer cannot see — " +
			"zero-width spaces, or bidirectional overrides that reorder how text " +
			"displays without changing what is read. The model reads the real " +
			"sequence. Anyone auditing the catalog reads the rendered one.",
		Steps: []Step{
			{"Strip the characters passmcp listed",
				"The finding gives their code points and shows them in context as " +
					"`<U+200B>`-style escapes."},
			{"Ask why they are there",
				"A bidirectional override in a tool description has no honest " +
					"explanation. Zero-width characters occasionally arrive by " +
					"accident through a copy-paste from a rich-text editor."},
		},
	},

	"catalog.text.secret_paths": {
		Means: "Catalog text names a place credentials live — an SSH key, an AWS " +
			"credentials file, a token environment variable. That may be accurate " +
			"and expected. It is also exactly what a poisoned description says " +
			"when it is trying to get one read and returned.",
		Steps: []Step{
			{"Confirm the tool really does this",
				"If it does, say so in prose an operator approves before installing, " +
					"not in a schema field."},
			{"If it does not, delete the reference",
				"A description that names a credential path it never touches is " +
					"either a leftover or a probe."},
		},
	},

	"catalog.names.confusable": {
		Means: "A name mixes scripts — Latin with Cyrillic or Greek letters that " +
			"render identically. That is not how a name is written by accident; " +
			"it is how one tool is made to look like another the user already " +
			"trusts.",
		Steps: []Step{
			{"Rename it in a single script",
				"The finding names which scripts were mixed."},
			{"Check what it resembles",
				"The interesting question is which existing tool the rendered name " +
					"matches."},
		},
	},
}
