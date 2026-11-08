package urdna2015

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// What Canonicalize signs must hold every value of the document: a value
// JSON-LD processing leaves out of the dataset, or rewrites, would ride the
// document unsigned. What is signed is the dataset, the document's meaning:
// spellings JSON-LD gives one RDF term are signed as that term (an IRI written
// as a term, a compact IRI or in full; a language tag in any ASCII case; a
// string with xsd:string written or not; a boolean written as true or false,
// or as the string of its name typed xsd:boolean), and the values of a
// property outside a list are signed as a set, in no order. A blank node label
// in the document is refused (rejectDroppableNodes): RDFC-1.0 gives every
// blank node a label of its own, so what a label says would not be signed.
// JSON-LD 1.1 Processing Algorithms and API leaves values out at many steps
// (Expansion, Node Map Generation, Deserialize JSON-LD to RDF), and json-gold
// expands the document a second time inside ToRDF. Rather than list the forms
// that lose a value, Canonicalize counts the document's values through each
// stage and refuses a document whose count changes:
//
//   - dataValues counts, in the document, the values JSON-LD carries into
//     the expanded form one for one: each string or boolean outside a
//     context, but a value object's @type and @language. expandedValues
//     counts the same in the expanded form: each @value, each @id, and each
//     @type of a node. The two must be equal.
//   - The node map's walk (nodemap.go) then requires each value to belong to
//     a node's property, each node object to add a quad of its own, and no
//     node's property to hold one RDF term twice, and counts the quads they
//     make: the dataset json-gold builds must hold exactly that many (holds).
//
// A count holds only where a value stays one value at every stage, so the
// document and every context it can use are first held to the forms where it
// does: no @index or @direction in the document (RDF does not carry them),
// @language only in a value object, a language tag of ASCII letters, digits
// and hyphens in a value object or a context (json-gold lowercases a tag with
// Unicode case mapping, so "\u0130t" would be "it"), a value object's keys
// written as the keywords @value, @type and @language, no term with a map
// container (@id, @type, @index or @language), whose keys become values, and
// no @base in a context: the RDFC path resolves no relative IRI against a
// base, so one stays relative and is refused, and two spellings of one IRI
// cannot be signed as one. dataValues leaves out only what is written as a
// keyword (@context, and a value object's @type and @language), so its count
// rests on no alias: a key JSON-LD reads as a keyword, through an alias or a
// vocabulary, is counted as a value unless it is written as one, and can only
// make the counts disagree. The aliases contexts write are read only to refuse
// by name, with no alias of @value, no term aliasing two keywords
// (contextRules.alias), and no @vocab beginning with @, which would make keys
// keywords. A JSON literal (@json) is refused too: written in the document,
// before it is expanded; by a term's @type, once expanded
// (rejectDroppableNodes), before ToRDF, whose canonical JSON takes time in the
// square of the literal's members. Once expanded, a value object must have at
// most one datatype, not rdf:JSON, and a boolean none but xsd:boolean
// (rejectLossyValue), as json-gold would keep one datatype, rewrite the JSON,
// or write a boolean as the string of its name; and the RDF collection
// vocabulary is not written out (rejectDroppableNodes), as it would be signed
// as the list @list makes.
//
// A context's own text is not signed: a term the document does not use adds
// nothing to the dataset, and dataValues counts no value of a context.

// contextRules is what Canonicalize reads from a context: the keyword each
// alias stands for. Reading a context refuses one defining a map container.
type contextRules struct {
	aliases map[string]string
}

func newContextRules() *contextRules {
	return &contextRules{aliases: map[string]string{}}
}

// read reads the term definitions of a context value: an object, an array of
// contexts, or the IRI of a remote one (read where the Canonicalizer serves
// it). Scoped contexts, and a context nested in a context, are read with the
// rest: an alias counts wherever it is defined (see alias for why that is
// safe). A keyword it does not know as a context's key is refused, so every
// map container json-gold reads is read here.
func (r *contextRules) read(ctx any) error {
	switch t := ctx.(type) {
	case []any:
		for _, c := range t {
			if err := r.read(c); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, term := range sortedKeys(t) {
			def := t[term]
			if strings.HasPrefix(term, "@") {
				switch term {
				case "@context":
					// json-gold reads a context nested in a context as part
					// of it.
					if err := r.read(def); err != nil {
						return err
					}
				case "@vocab":
					// A key the vocabulary maps is the vocabulary and the key
					// joined: one beginning with @ would make keys keywords.
					if v, ok := def.(string); ok && strings.HasPrefix(v, "@") {
						return fmt.Errorf("urdna2015: context @vocab %s begins with @, which would make keys keywords", bounded(v))
					}
				case "@base":
					// The RDFC path resolves no relative IRI against a base:
					// one stays relative, and is refused.
					if def != nil {
						return fmt.Errorf("urdna2015: context @base %s: the RDFC path resolves no relative IRI against a base", bounded(fmt.Sprint(def)))
					}
				case "@language":
					if err := asciiLanguage(def); err != nil {
						return err
					}
				case "@direction", "@version", "@protected", "@propagate", "@import", "@type":
				default:
					return fmt.Errorf("urdna2015: context keyword %s is not one the RDFC path reads", bounded(term))
				}
				continue
			}
			switch d := def.(type) {
			case string:
				if ld.IsKeyword(d) {
					if err := r.alias(term, d); err != nil {
						return err
					}
				}
			case map[string]any:
				if language, ok := d["@language"]; ok {
					if err := asciiLanguage(language); err != nil {
						return err
					}
				}
				if id, ok := d["@id"].(string); ok && ld.IsKeyword(id) {
					if err := r.alias(term, id); err != nil {
						return err
					}
				}
				containers, ok := d["@container"].([]any)
				if !ok {
					containers = []any{d["@container"]}
				}
				for _, c := range containers {
					switch c {
					case "@id", "@type", "@index", "@language":
						return fmt.Errorf("urdna2015: context term %s has a %s container: its keys become values, which the RDFC path does not accept", bounded(term), c)
					}
				}
				if scoped, ok := d["@context"]; ok {
					if err := r.read(scoped); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// asciiLanguage refuses a language tag, in a value object or a context,
// that is not of the ASCII grammar quad validity uses: json-gold lowercases
// a tag with Unicode case mapping before that grammar is applied, so "\u0130t"
// would be signed as "it". A context's null language is let through.
func asciiLanguage(language any) error {
	if language == nil {
		return nil
	}
	if s, ok := language.(string); ok && validLanguageRegex.MatchString(s) {
		return nil
	}
	return fmt.Errorf("urdna2015: @language %s is not a tag of ASCII letters, digits and hyphens: json-gold lowercases it with Unicode case mapping, so two spellings would be signed as one", bounded(fmt.Sprint(language)))
}

// alias records that term stands for keyword. An alias of @value written in
// a context is refused; and a term two definitions alias to different
// keywords is refused, so each term reads as one keyword in whatever order
// the definitions are read. The aliases read here are not all json-gold's:
// one may be in a scope not in use, and a term of a term of a keyword is not
// read. They are used only to refuse (@index, @direction, or @language
// outside a value object) by name: no value is left uncounted by an alias,
// since dataValues knows a value object by @value written out and reads its
// keys only as the keywords written out, so an alias read wrong, or not
// read, can only refuse.
func (r *contextRules) alias(term, keyword string) error {
	if keyword == "@value" {
		return fmt.Errorf("urdna2015: context term %s is an alias of @value: the RDFC path knows a value object by @value alone", bounded(term))
	}
	if was, ok := r.aliases[term]; ok && was != keyword {
		return fmt.Errorf("urdna2015: context term %s aliases both %s and %s: the RDFC path reads each term as one keyword", bounded(term), bounded(was), bounded(keyword))
	}
	r.aliases[term] = keyword
	return nil
}

// readDocument reads every context the document holds, wherever it is. A
// context's scoped contexts are read with it (read), not again here, so each
// is read once.
func (r *contextRules) readDocument(v any) error {
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if err := r.readDocument(x); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			x := t[k]
			if k == "@context" {
				if err := r.read(x); err != nil {
					return err
				}
				continue
			}
			if err := r.readDocument(x); err != nil {
				return err
			}
		}
	}
	return nil
}

// readServed reads the contexts a Canonicalizer serves, parsed as its
// loader parses them (offlineLoader), so the rules read what json-gold reads.
// A document that is not JSON is left to the loader to report.
func (r *contextRules) readServed(contexts map[string][]byte) error {
	for _, iri := range sortedKeys(contexts) {
		var doc map[string]any
		// decoder-hygiene-exempt: the served contexts, read as offlineLoader reads them.
		if json.Unmarshal(contexts[iri], &doc) != nil {
			continue
		}
		if err := r.read(doc["@context"]); err != nil {
			return fmt.Errorf("%w (in the served context %s)", err, iri)
		}
	}
	return nil
}

// keyword is the keyword a key stands for, or "".
func (r *contextRules) keyword(key string) string {
	if strings.HasPrefix(key, "@") {
		return key
	}
	return r.aliases[key]
}

// dataValues counts the document's values JSON-LD carries into the expanded
// form one for one (see the comment at the top of this file), refusing @index
// and @direction anywhere, and @language outside a value object.
func (r *contextRules) dataValues(v any, path *jsonPath) (int64, error) {
	switch t := v.(type) {
	case string, bool:
		return 1, nil
	case []any:
		var n int64
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			m, err := r.dataValues(x, path)
			if err != nil {
				return 0, err
			}
			*path = (*path)[:len(*path)-1]
			n += m
		}
		return n, nil
	case map[string]any:
		keys := sortedKeys(t)
		value, language := false, false
		for _, k := range keys {
			switch r.keyword(k) {
			case "@value":
				value = true
			case "@language":
				language = true
			case "@index":
				return 0, fmt.Errorf("urdna2015: @index at %q: RDF does not carry it, so it would ride the document unsigned", path.String())
			case "@direction":
				return 0, fmt.Errorf("urdna2015: @direction at %q: json-gold does not write base direction, so it would ride the document unsigned", path.String())
			}
		}
		if language && !value {
			return 0, fmt.Errorf("urdna2015: @language at %q outside a value object: JSON-LD drops it, so it would ride the document unsigned", path.String())
		}
		if value {
			for _, k := range keys {
				x := t[k]
				switch k {
				case "@value":
				case "@language":
					if err := asciiLanguage(x); err != nil {
						return 0, err
					}
				case "@type":
					if x == "@json" {
						return 0, fmt.Errorf("urdna2015: @json at %q: the RDFC path does not accept JSON literals", path.String())
					}
				default:
					return 0, fmt.Errorf("urdna2015: a value object at %q holds %s: the RDFC path reads a value object's keys only as the keywords written out (@value, @type, @language)", path.String(), bounded(k))
				}
			}
		}
		var n int64
		for _, k := range keys {
			x := t[k]
			switch {
			case k == "@context":
			case value && (k == "@type" || k == "@language"):
			default:
				*path = append(*path, pathSegment{key: k, index: -1})
				m, err := r.dataValues(x, path)
				if err != nil {
					return 0, err
				}
				*path = (*path)[:len(*path)-1]
				n += m
			}
		}
		return n, nil
	}
	return 0, nil
}

// expandedValues counts the values of an expanded document dataValues counts
// in the document: each @value that is a string or a boolean, each @id, and
// each @type of a node.
func expandedValues(v any) int64 {
	switch t := v.(type) {
	case []any:
		var n int64
		for _, x := range t {
			n += expandedValues(x)
		}
		return n
	case map[string]any:
		if x, ok := t["@value"]; ok {
			switch x.(type) {
			case string, bool:
				return 1
			}
			return 0
		}
		var n int64
		for k, x := range t {
			switch k {
			case "@id":
				if _, ok := x.(string); ok {
					n++
				}
			case "@type":
				n += stringsIn(x)
			case "@language", "@index", "@direction":
			default:
				n += expandedValues(x)
			}
		}
		return n
	}
	return 0
}

func stringsIn(v any) int64 {
	switch t := v.(type) {
	case string:
		return 1
	case []any:
		var n int64
		for _, x := range t {
			n += stringsIn(x)
		}
		return n
	}
	return 0
}
