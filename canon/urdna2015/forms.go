package urdna2015

import (
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// The walk of the document's forms accepts only the forms JSON-LD signs, and
// refuses the rest, before JSON-LD processing runs. Two kinds are refused:
//
//   - forms in which a value would not stay one value, so the count of
//     values (conserve.go) could not hold (rejectUncountedForms): @index,
//     @direction, @set and the framing keywords, @language outside a value
//     object, and a value object's other keys, a language tag not of ASCII,
//     and a JSON literal;
//   - shapes of the JSON the dataset does not hold: an empty object or array
//     JSON-LD keeps nothing of, an array in an array, which json-gold
//     flattens into the outer one, a list where JSON-LD keeps none, and a
//     keyword it does not read. They hold no value the counts would miss, but
//     a JSON reader sees them and the signature would not hold them, so they
//     are refused as a value written twice is.
//
// A document uses only the shapes JSON-LD signs:
//
//   - an empty object only as a property's value, or an item of it or of a
//     list (a blank node);
//   - an empty array only as a property's whole value, wherever a property
//     is (no quad: a property with no values), or as a list's items where a
//     list is kept (the empty list);
//   - an array only as a value, never as an item of another array;
//   - a list only as a property's value, or an item of it or of a list, and a
//     value object only there too (the walk refuses one at a node; as the
//     value of @id, @type or @reverse, json-gold refuses it);
//   - as members, besides properties, only the keywords JSON-LD reads in a
//     document: @context, @id, @type, @value, @language, @list, @graph,
//     @reverse, @included and @nest.
//
// An object of only @context is empty: a context's own text is not signed. A
// @nest group's members are signed as the members of the object holding it,
// so they are held to that object's position.
//
// A key is read as a keyword through the aliases the context rules read, one
// step, a longer chain being refused (rejectAliasChains): exact for the
// contexts vc serves. In a document's own contexts (WithLocalContexts), a
// term a scope not in use makes a keyword is read as one, so a shape it holds
// may be refused though signed: under a term such a scope makes @graph or
// @included, an empty object, a list or a value object is read as at a node.

// position is where a value sits in a document, for the shapes JSON-LD signs
// there.
type position int

const (
	// atNode is the document, or an item of its array, of @graph or of
	// @included: JSON-LD keeps there only a node that adds a quad.
	atNode position = iota
	// atProperty is a property's value, or an item of it.
	atProperty
	// atList is an item of a list.
	atList
	// atKeyword is the value of @id, @type or @reverse (whose members are
	// properties).
	atKeyword
)

// keywordsRead are the keywords JSON-LD reads as a member of a document's
// node, list or value objects; @set, @index, @direction and the framing
// keywords are refused before this, with reasons of their own
// (rejectUncountedForms).
var keywordsRead = map[string]bool{
	"@context": true, "@id": true, "@type": true, "@value": true, "@language": true,
	"@list": true, "@graph": true, "@reverse": true, "@included": true, "@nest": true,
}

// rejectUnsignedForms refuses the first shape of v, at position at, that the
// dataset would not hold (see the comment at the top of this file). path is
// where v is, for the error.
func (r *contextRules) rejectUnsignedForms(v any, at position, path *jsonPath) error {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 && at != atProperty {
			return fmt.Errorf("urdna2015: an empty array at %s: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.quoted())
		}
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			if _, ok := x.([]any); ok {
				return fmt.Errorf("urdna2015: an array in an array at %s: json-gold flattens it into the outer one, so how it is nested would ride the document unsigned", path.quoted())
			}
			if err := r.rejectUnsignedForms(x, at, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		keys := sortedKeys(t)
		value, err := r.rejectUncountedForms(t, keys, path)
		if err != nil {
			return err
		}
		if value {
			// A value object holds a scalar, or a JSON literal, refused with
			// its keys; JSON-LD keeps one only as a property's value or an
			// item of it or of a list. As the value of @id, @type or
			// @reverse, json-gold refuses it.
			if at == atNode {
				return fmt.Errorf("urdna2015: a value object at %s, where JSON-LD keeps none, so it would ride the document unsigned", path.quoted())
			}
			return nil
		}
		members := 0
		for _, k := range keys {
			if r.keyword(k) != "@context" {
				members++
			}
		}
		if members == 0 && at != atProperty && at != atList {
			return fmt.Errorf("urdna2015: an empty object at %s: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.quoted())
		}
		return r.rejectUnsignedMembers(t, keys, at, path)
	}
	return nil
}

// rejectUnsignedMembers refuses the first shape of the members of obj, an
// object at position at, the dataset would not hold.
func (r *contextRules) rejectUnsignedMembers(obj map[string]any, keys []string, at position, path *jsonPath) error {
	for _, k := range keys {
		x := obj[k]
		kw := r.keyword(k)
		if kw == "@context" {
			continue
		}
		*path = append(*path, pathSegment{key: k, index: -1})
		var err error
		switch {
		case kw == "", !ld.IsKeyword(kw):
			// A name beginning with @ that is no keyword is a property under
			// a @vocab, and refused otherwise by json-gold's safe mode.
			err = r.rejectUnsignedForms(x, atProperty, path)
		case kw == "@graph", kw == "@included":
			err = r.rejectUnsignedForms(x, atNode, path)
		case kw == "@list":
			err = r.rejectUnsignedList(x, at, path)
		case kw == "@nest":
			err = r.rejectUnsignedNest(x, at, path)
		case keywordsRead[kw]:
			err = r.rejectUnsignedForms(x, atKeyword, path)
		default:
			err = fmt.Errorf("urdna2015: %s at %s: JSON-LD reads no such member in a document, so what it holds would ride the document unsigned", bounded(k), path.quoted())
		}
		if err != nil {
			return err
		}
		*path = (*path)[:len(*path)-1]
	}
	return nil
}

// rejectUnsignedNest refuses a @nest group, of an object at position at, that
// is empty, and the first shape of its members the dataset would not hold:
// JSON-LD signs a group's members as the members of the object holding it, so
// they are held to that object's position. A group that is not an object, or
// an array of them, is left to json-gold, which refuses it.
func (r *contextRules) rejectUnsignedNest(group any, at position, path *jsonPath) error {
	switch t := group.(type) {
	case []any:
		if len(t) == 0 {
			return fmt.Errorf("urdna2015: an empty array at %s: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.quoted())
		}
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			if _, ok := x.([]any); ok {
				return fmt.Errorf("urdna2015: an array in an array at %s: json-gold flattens it into the outer one, so how it is nested would ride the document unsigned", path.quoted())
			}
			if err := r.rejectUnsignedNest(x, at, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		keys := sortedKeys(t)
		if value, err := r.rejectUncountedForms(t, keys, path); err != nil || value {
			// json-gold refuses a group holding @value.
			return err
		}
		members := 0
		for _, k := range keys {
			if r.keyword(k) != "@context" {
				members++
			}
		}
		if members == 0 {
			return fmt.Errorf("urdna2015: an empty object at %s: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.quoted())
		}
		return r.rejectUnsignedMembers(t, keys, at, path)
	}
	return nil
}

// rejectUncountedForms refuses, in obj, the forms in which a value would not
// stay one value, so the count of values (conserve.go) could not hold:
// @index and @direction, which RDF does not carry; @set and the framing
// keywords, under which json-gold drops what it cannot expand without an
// error; @language outside a value object, which JSON-LD drops; and, in a
// value object, a key other than @value, @type and @language written out, a
// language tag not of ASCII letters, digits and hyphens, and a JSON literal
// ("@json" as its @type, alone or in an array). A keyword is read through the
// aliases the context rules read, but a value object's keys, and its @type,
// only as written. It reports whether obj is a value object.
func (r *contextRules) rejectUncountedForms(obj map[string]any, keys []string, path *jsonPath) (value bool, err error) {
	language := false
	for _, k := range keys {
		switch r.keyword(k) {
		case "@value":
			value = true
		case "@language":
			language = true
		case "@index":
			return false, fmt.Errorf("urdna2015: @index at %s: RDF does not carry it, so it would ride the document unsigned", path.quoted())
		case "@direction":
			return false, fmt.Errorf("urdna2015: @direction at %s: json-gold does not write base direction, so it would ride the document unsigned", path.quoted())
		case "@set":
			return false, fmt.Errorf("urdna2015: @set at %s: json-gold drops what it cannot expand under @set without an error, so it would ride the document unsigned; write the set's values without @set", path.quoted())
		case "@default", "@explicit", "@embed", "@requireAll", "@omitDefault":
			return false, fmt.Errorf("urdna2015: %s at %s: a framing keyword, which a document does not use; json-gold drops what it cannot expand under it without an error, so it would ride the document unsigned", r.keyword(k), path.quoted())
		}
	}
	if language && !value {
		return false, fmt.Errorf("urdna2015: @language at %s outside a value object: JSON-LD drops it, so it would ride the document unsigned", path.quoted())
	}
	if value {
		for _, k := range keys {
			x := obj[k]
			switch k {
			case "@value":
			case "@language":
				if err := asciiLanguage(x); err != nil {
					return false, err
				}
			case "@type":
				if jsonLiteral(x) {
					return false, fmt.Errorf("urdna2015: @json at %s: the RDFC path does not accept JSON literals", path.quoted())
				}
			default:
				return false, fmt.Errorf("urdna2015: a value object at %s holds %s: the RDFC path reads a value object's keys only as the keywords written out (@value, @type, @language)", path.quoted(), bounded(k))
			}
		}
	}
	return value, nil
}

// rejectUnsignedList refuses the items of a list, its object at position at,
// where JSON-LD keeps no list, and the shapes of its items it would not sign.
// An empty list is kept where a list is: its items are signed as rdf:nil.
func (r *contextRules) rejectUnsignedList(items any, at position, path *jsonPath) error {
	if at != atProperty && at != atList {
		return fmt.Errorf("urdna2015: a list at %s, where JSON-LD keeps no list, so it would ride the document unsigned", path.quoted())
	}
	if list, ok := items.([]any); ok && len(list) == 0 {
		return nil
	}
	return r.rejectUnsignedForms(items, atList, path)
}

// jsonLiteral reports whether a value object's @type makes it a JSON literal:
// "@json", alone or in an array, which JSON-LD reads as the same. An alias of
// @json is refused with the context (contextRules.alias), so it is read only
// as written.
func jsonLiteral(datatype any) bool {
	types, ok := datatype.([]any)
	if !ok {
		types = []any{datatype}
	}
	for _, t := range types {
		if t == "@json" {
			return true
		}
	}
	return false
}
