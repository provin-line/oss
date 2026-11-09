package urdna2015

import (
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// A document's JSON holds shapes the dataset does not: an empty object or
// array JSON-LD keeps nothing of, an array in an array, which json-gold
// flattens into the outer one, a list where JSON-LD keeps none, and a keyword
// it does not read. They hold no value the counts would miss (conserve.go),
// but a JSON reader sees them and the signature would not hold them, so
// Canonicalize refuses them, as it refuses a value written twice. A document
// uses only the shapes JSON-LD signs:
//
//   - an empty object only as a property's value, or an item of it or of a
//     list (a blank node);
//   - an empty array only as a property's whole value, wherever a property
//     is (no quad: a property with no values), or as a list's items where a
//     list is kept (the empty list);
//   - an array only as a value, never as an item of another array;
//   - a list only as a property's value, or an item of it or of a list;
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
// contexts vc serves. In a document's own contexts, a term a scope not in use
// makes a keyword is read as one, so a shape it holds may be refused though
// signed.

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
// keywords are refused before this, with reasons of their own (dataValues).
var keywordsRead = map[string]bool{
	"@context": true, "@id": true, "@type": true, "@value": true, "@language": true,
	"@list": true, "@graph": true, "@reverse": true, "@included": true, "@nest": true,
}

// rejectUnsignedShapes refuses the first shape of v, at position at, that the
// dataset would not hold (see the comment at the top of this file). path is
// where v is, for the error.
func (r *contextRules) rejectUnsignedShapes(v any, at position, path *jsonPath) error {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 && at != atProperty {
			return fmt.Errorf("urdna2015: an empty array at %q: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.String())
		}
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			if _, ok := x.([]any); ok {
				return fmt.Errorf("urdna2015: an array in an array at %q: json-gold flattens it into the outer one, so how it is nested would ride the document unsigned", path.String())
			}
			if err := r.rejectUnsignedShapes(x, at, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		keys := sortedKeys(t)
		members := 0
		for _, k := range keys {
			switch kw := r.keyword(k); {
			case kw == "@value":
				// A value object holds a scalar, its keys checked by
				// dataValues.
				return nil
			case kw != "@context":
				members++
			}
		}
		if members == 0 && at != atProperty && at != atList {
			return fmt.Errorf("urdna2015: an empty object at %q: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.String())
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
			err = r.rejectUnsignedShapes(x, atProperty, path)
		case kw == "@graph", kw == "@included":
			err = r.rejectUnsignedShapes(x, atNode, path)
		case kw == "@list":
			err = r.rejectUnsignedList(x, at, path)
		case kw == "@nest":
			err = r.rejectUnsignedNest(x, at, path)
		case keywordsRead[kw]:
			err = r.rejectUnsignedShapes(x, atKeyword, path)
		default:
			err = fmt.Errorf("urdna2015: %s at %q: JSON-LD reads no such member in a document, so what it holds would ride the document unsigned", bounded(k), path.String())
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
			return fmt.Errorf("urdna2015: an empty array at %q: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.String())
		}
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			if _, ok := x.([]any); ok {
				return fmt.Errorf("urdna2015: an array in an array at %q: json-gold flattens it into the outer one, so how it is nested would ride the document unsigned", path.String())
			}
			if err := r.rejectUnsignedNest(x, at, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		keys := sortedKeys(t)
		members := 0
		for _, k := range keys {
			if r.keyword(k) != "@context" {
				members++
			}
		}
		if members == 0 {
			return fmt.Errorf("urdna2015: an empty object at %q: JSON-LD keeps nothing of it there, so it would ride the document unsigned", path.String())
		}
		return r.rejectUnsignedMembers(t, keys, at, path)
	}
	return nil
}

// rejectUnsignedList refuses the items of a list, its object at position at,
// where JSON-LD keeps no list, and the shapes of its items it would not sign.
// An empty list is kept where a list is: its items are signed as rdf:nil.
func (r *contextRules) rejectUnsignedList(items any, at position, path *jsonPath) error {
	if at != atProperty && at != atList {
		return fmt.Errorf("urdna2015: a list at %q, where JSON-LD keeps no list, so it would ride the document unsigned", path.String())
	}
	if list, ok := items.([]any); ok && len(list) == 0 {
		return nil
	}
	return r.rejectUnsignedShapes(items, atList, path)
}
