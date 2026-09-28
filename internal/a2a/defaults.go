// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

// SigningPayload returns the bytes an Agent Card signature covers: the card
// without its `signatures` member, with default values removed, in RFC 8785
// canonical form (A2A v1.0 section 8.4.1 and 8.4.3).
//
// Removing defaults is what lets a verifier that re-serialises the card
// agree with the signer. A field is kept when the proto marks it REQUIRED
// or `optional` (explicit presence), and dropped when it holds its default
// otherwise: an empty string or list, false, zero, or an empty map. A
// message-valued field is kept (a present message is explicitly set) and
// its own members are processed the same way. Members the proto does not
// declare, and the contents of google.protobuf.Struct fields, are kept as
// they are: nothing defines their defaults.
func SigningPayload(card map[string]any) ([]byte, error) {
	body := make(map[string]any, len(card))
	for k, v := range card {
		if k != "signatures" {
			body[k] = v
		}
	}
	return canonicalValue(stripObject(body, agentCard))
}

func stripObject(m map[string]any, s *shape) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		f, known := s.fields[k]
		if !known {
			out[k] = v
			continue
		}
		if !f.required && !f.optional && isDefault(v, f) {
			continue
		}
		out[k] = stripValue(v, f)
	}
	return out
}

// isDefault reports whether v is the proto3 default for a field without
// explicit presence. A message value is never a default: sending one at
// all is setting it.
func isDefault(v any, f field) bool {
	switch f.kind {
	case kString:
		return v == ""
	case kBool:
		return v == false
	case kArray:
		a, ok := v.([]any)
		return ok && len(a) == 0
	case kMap, kStringMap:
		m, ok := v.(map[string]any)
		return ok && len(m) == 0
	}
	return false
}

func stripValue(v any, f field) any {
	switch f.kind {
	case kObject:
		if m, ok := v.(map[string]any); ok {
			return stripObject(m, f.elem)
		}
	case kArray:
		if a, ok := v.([]any); ok && f.elem != nil {
			out := make([]any, len(a))
			for i, e := range a {
				out[i] = stripValue(e, field{kind: kObject, elem: f.elem})
			}
			return out
		}
	case kMap:
		if m, ok := v.(map[string]any); ok {
			out := make(map[string]any, len(m))
			for k, e := range m {
				out[k] = stripValue(e, field{kind: kObject, elem: f.elem})
			}
			return out
		}
	}
	return v
}
