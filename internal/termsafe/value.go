// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package termsafe

import "reflect"

// Value returns v with String applied to every string reachable from it
// through exported struct fields, pointers, slices, arrays, maps and
// interfaces.
//
// It is for a renderer that takes a whole document, such as a report,
// whose strings come from many places: cleaning the document on the way
// in is one call, where cleaning at every print site is a list somebody
// forgets to extend. v itself is never modified. When nothing in it needs
// cleaning — the usual case — v is returned as it is and nothing is
// copied; otherwise the parts that lead to a changed string are copied
// and the rest is shared.
func Value[T any](v T) T {
	rv := reflect.ValueOf(&v).Elem()
	if out, changed := clean(rv); changed {
		return out.Interface().(T)
	}
	return v
}

// clean returns a cleaned copy of v and true, or v and false when nothing
// under it changed.
func clean(v reflect.Value) (reflect.Value, bool) {
	switch v.Kind() {
	case reflect.String:
		return cleanString(v)
	case reflect.Pointer:
		return cleanPointer(v)
	case reflect.Interface:
		return cleanInterface(v)
	case reflect.Struct:
		return cleanStruct(v)
	case reflect.Slice, reflect.Array:
		return cleanList(v)
	case reflect.Map:
		return cleanMap(v)
	}
	return v, false
}

func cleanString(v reflect.Value) (reflect.Value, bool) {
	s := v.String()
	c := String(s)
	if c == s {
		return v, false
	}
	out := reflect.New(v.Type()).Elem()
	out.SetString(c)
	return out, true
}

func cleanPointer(v reflect.Value) (reflect.Value, bool) {
	if v.IsNil() {
		return v, false
	}
	elem, changed := clean(v.Elem())
	if !changed {
		return v, false
	}
	out := reflect.New(v.Type().Elem())
	out.Elem().Set(elem)
	return out, true
}

func cleanInterface(v reflect.Value) (reflect.Value, bool) {
	if v.IsNil() {
		return v, false
	}
	elem, changed := clean(v.Elem())
	if !changed {
		return v, false
	}
	out := reflect.New(v.Type()).Elem()
	out.Set(elem)
	return out, true
}

// cleanStruct copies the whole struct, unexported fields included, and
// then replaces the exported fields that changed. Unexported fields are
// not descended into: reflection cannot set them, and nothing a renderer
// prints is kept in one.
func cleanStruct(v reflect.Value) (reflect.Value, bool) {
	var out reflect.Value
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		f, changed := clean(v.Field(i))
		if !changed {
			continue
		}
		if !out.IsValid() {
			out = reflect.New(t).Elem()
			out.Set(v)
		}
		out.Field(i).Set(f)
	}
	if !out.IsValid() {
		return v, false
	}
	return out, true
}

// cleanList cleans each element. Bytes are not text to a renderer that
// prints them, and walking a captured body one byte at a time would cost
// more than the rest of the report, so a byte slice is left alone.
func cleanList(v reflect.Value) (reflect.Value, bool) {
	if v.Type().Elem().Kind() == reflect.Uint8 {
		return v, false
	}
	var out reflect.Value
	for i := 0; i < v.Len(); i++ {
		e, changed := clean(v.Index(i))
		if !changed {
			continue
		}
		if !out.IsValid() {
			out = copyList(v)
		}
		out.Index(i).Set(e)
	}
	if !out.IsValid() {
		return v, false
	}
	return out, true
}

// copyList returns a settable copy of a slice or array.
func copyList(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Array {
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		return out
	}
	out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
	reflect.Copy(out, v)
	return out
}

// cleanMap cleans keys as well as values: a map keyed by a check id or a
// tool name is printed by its keys. A clean map is walked once and not
// copied.
func cleanMap(v reflect.Value) (reflect.Value, bool) {
	if v.IsNil() || !mapNeeds(v) {
		return v, false
	}
	out := reflect.MakeMapWithSize(v.Type(), v.Len())
	it := v.MapRange()
	for it.Next() {
		k, _ := clean(it.Key())
		e, _ := clean(it.Value())
		out.SetMapIndex(k, e)
	}
	return out, true
}

// mapNeeds reports whether any key or value of v would change.
func mapNeeds(v reflect.Value) bool {
	it := v.MapRange()
	for it.Next() {
		if _, changed := clean(it.Key()); changed {
			return true
		}
		if _, changed := clean(it.Value()); changed {
			return true
		}
	}
	return false
}
