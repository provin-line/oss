package urdna2015

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// validLanguageRegex mirrors json-gold's quad-validity language grammar
// (ld.InvalidNode): a literal whose language fails it is dropped from the
// dataset without error, so the same grammar rejects here instead.
var validLanguageRegex = regexp.MustCompile(`^[a-zA-Z]+(-[a-zA-Z0-9]+)*$`)

// validEmittedIRI reports whether s survives toRDF as an IRI node: absolute
// by expansion rules AND valid under json-gold's own quad sanitization
// (ld.InvalidNode), which additionally URL-validates http(s) IRIs. Both
// filters drop silently, so both are mirrored.
func validEmittedIRI(s string) bool {
	return ld.IsAbsoluteIri(s) && !ld.InvalidNode(ld.NewIRI(s))
}

// rejectLossyValue refuses an expanded value object whose datatype json-gold
// would not write as it is: more than one datatype (it keeps the first), a
// JSON literal (@json or rdf:JSON: it rewrites the value as canonical JSON,
// in time in the square of its members), or a datatype on a boolean other
// than xsd:boolean (it writes the boolean as the string of its name with that
// datatype, the same literal as that string's, so which of the two the
// document holds would not be signed; with xsd:boolean the literal is the
// boolean's own).
func rejectLossyValue(value, datatype any) error {
	if datatype == nil {
		return nil
	}
	if _, ok := datatype.(string); !ok {
		return fmt.Errorf("urdna2015: a value object with %s as its datatype: json-gold keeps one datatype, so the others would ride the document unsigned", bounded(fmt.Sprint(datatype)))
	}
	if datatype == "@json" || datatype == ld.RDFJSONLiteral {
		return fmt.Errorf("urdna2015: a JSON literal (@json, rdf:JSON): json-gold rewrites it as canonical JSON, so how it is written would ride the document unsigned")
	}
	if _, ok := value.(bool); ok && datatype != xsdBoolean {
		return fmt.Errorf("urdna2015: a boolean value with a datatype other than xsd:boolean: it is signed as the same literal as the string of its name, so which the document holds would ride it unsigned")
	}
	return nil
}

const (
	xsdString  = "http://www.w3.org/2001/XMLSchema#string"
	xsdBoolean = "http://www.w3.org/2001/XMLSchema#boolean"
	rdfFirst   = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first"
	rdfRest    = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"
	rdfNil     = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
)

// besideListOrSet is what json-gold makes of an expanded list or set object
// holding another key, which its expansion lets through where the object has
// a @type: of a list object, its node map makes the list alone; a set
// object, it reads as a node and drops the set's values.
var besideListOrSet = []struct{ keyword, makes string }{
	{"@list", "JSON-LD keeps the list alone, so it would ride the document unsigned"},
	{"@set", "JSON-LD reads the object as a node and drops the set's values, so they would ride the document unsigned"},
}

// rejectListBeside refuses an expanded list object holding a key beside
// @list, and an expanded object holding @set beside another key
// (besideListOrSet). Expanded, a set object is otherwise replaced by its
// values; @set written in a document is refused before expansion
// (rejectUncountedForms), so this is reached through an alias the context
// rules do not read.
func rejectListBeside(obj map[string]any) error {
	for _, b := range besideListOrSet {
		if _, ok := obj[b.keyword]; !ok || len(obj) == 1 {
			continue
		}
		for _, k := range sortedKeys(obj) {
			if k != b.keyword {
				return fmt.Errorf("urdna2015: %s beside %s: %s", bounded(k), b.keyword, b.makes)
			}
		}
	}
	return nil
}

// collectionWrittenOut is the refusal of the RDF collection vocabulary
// written out (see rejectDroppableNodes).
const collectionWrittenOut = "urdna2015: rdf:first or rdf:rest as a property, or rdf:nil as an IRI: it would be signed as the list @list makes, which a JSON reader does not see; write a list with @list"

// expandedKeywords are the keywords the expanded form of a document holds
// besides those rejectDroppableNodes reads itself (@id, @type, @index,
// @direction, @language): the members of a value, list, graph, reverse or
// included object. Any other keyword in the expanded form holds what toRDF
// writes no quad of.
var expandedKeywords = map[string]bool{
	"@value": true, "@list": true, "@graph": true, "@reverse": true, "@included": true,
}

// rejectDroppableNodes walks an EXPANDED JSON-LD document and fails on the
// shapes toRDF discards without error even in safe mode: an @id, a @type or a
// predicate that is not an absolute IRI, or fails json-gold's own quad
// validity (ld.InvalidNode, mirrored by validEmittedIRI); a blank-node
// predicate or label; @index and @direction, which toRDF does not write; a
// @language failing json-gold's language grammar, which drops the whole
// literal (the same pattern, so all it accepts toRDF writes); and an item of
// a list json-gold could not expand. It fails, too, on the RDF collection
// vocabulary written out (rdf:first and rdf:rest as properties, rdf:nil as an
// IRI): it would be signed as the list @list makes, which a JSON reader does
// not see, so a list comes only from @list. After expansion every key is an
// absolute IRI or a keyword, so the walk needs no context awareness.
func rejectDroppableNodes(v any) error {
	switch t := v.(type) {
	case nil:
		// The expanded form holds null only where json-gold dropped the
		// error of an item it could not expand (under @list).
		return errors.New("urdna2015: an item JSON-LD could not expand: json-gold drops it without an error, so it would ride the document unsigned")
	case []any:
		for _, e := range t {
			if err := rejectDroppableNodes(e); err != nil {
				return err
			}
		}
	case map[string]any:
		if value, ok := t["@value"]; ok {
			if err := rejectLossyValue(value, t["@type"]); err != nil {
				return err
			}
		}
		if err := rejectListBeside(t); err != nil {
			return err
		}
		for _, k := range sortedKeys(t) {
			e := t[k]
			switch k {
			case "@id":
				id, ok := e.(string)
				if ok && strings.HasPrefix(id, "_:") {
					return fmt.Errorf("urdna2015: blank node label %s: RDFC-1.0 gives every blank node a label of its own, so the label would ride the document unsigned; write the node without @id", bounded(id))
				}
				if id == rdfNil {
					return errors.New(collectionWrittenOut)
				}
				if !ok || !validEmittedIRI(id) {
					return fmt.Errorf("urdna2015: @id %s is not a valid absolute IRI — toRDF would silently drop the node from the signing scope", bounded(fmt.Sprint(e)))
				}
			case "@type":
				// Covers both a node's types and a value object's datatype:
				// each must be a valid absolute IRI or the node/literal is
				// dropped. (This is also what rejects @json literals — their
				// datatype keyword is not an IRI — which provin's wire never
				// carries.)
				types, ok := e.([]any)
				if !ok {
					types = []any{e}
				}
				for _, tv := range types {
					name, ok := tv.(string)
					if ok && strings.HasPrefix(name, "_:") {
						return fmt.Errorf("urdna2015: blank node label %s as a type: RDFC-1.0 gives every blank node a label of its own, so the label would ride the document unsigned", bounded(name))
					}
					if name == rdfNil {
						return errors.New(collectionWrittenOut)
					}
					if !ok || !validEmittedIRI(name) {
						return fmt.Errorf("urdna2015: type %s does not expand to a valid absolute IRI — toRDF would silently drop it from the signing scope", bounded(fmt.Sprint(tv)))
					}
				}
			case "@index":
				// Index maps are a compaction convenience: expansion keeps
				// @index but toRDF emits nothing for it.
				return fmt.Errorf("urdna2015: @index member — toRDF emits no quads for it, so it would ride the document unsigned")
			case "@direction":
				// json-gold does not serialize base direction: value
				// objects differing only in @direction canonicalize
				// identically.
				return fmt.Errorf("urdna2015: @direction member — json-gold does not serialize base direction, so it would ride the document unsigned")
			case "@language":
				lang, ok := e.(string)
				if !ok || !validLanguageRegex.MatchString(lang) {
					return fmt.Errorf("urdna2015: @language %s fails the quad-validity language grammar — toRDF would silently drop the whole literal from the signing scope", bounded(fmt.Sprint(e)))
				}
			default:
				// A blank-node predicate is dropped by toRDF (generalized
				// RDF is off, pinned by options()); an IRI predicate failing
				// quad sanitization drops its quads too.
				if k == rdfFirst || k == rdfRest {
					return errors.New(collectionWrittenOut)
				}
				if strings.HasPrefix(k, "_:") {
					return fmt.Errorf("urdna2015: blank-node predicate %s — toRDF would silently drop it from the signing scope", bounded(k))
				}
				if ld.IsKeyword(k) && !expandedKeywords[k] {
					return fmt.Errorf("urdna2015: %s in the expanded form: toRDF writes no quad of it, so what it holds would ride the document unsigned", k)
				}
				if !ld.IsKeyword(k) && !validEmittedIRI(k) {
					return fmt.Errorf("urdna2015: predicate %s fails quad validation — toRDF would silently drop its quads from the signing scope", bounded(k))
				}
			}
			if err := rejectDroppableNodes(e); err != nil {
				return err
			}
		}
	}
	return nil
}
