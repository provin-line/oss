package urdna2015

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// contextRules is what Canonicalize reads from a context: the keyword each
// alias stands for, and the names each term's definitions give, terms or
// IRIs. Reading a context refuses one defining a map container.
type contextRules struct {
	aliases map[string]string
	names   map[string][]string
}

func newContextRules() *contextRules {
	return &contextRules{aliases: map[string]string{}, names: map[string][]string{}}
}

// copyOf is a copy of r, for a document's contexts to be read after r's.
func (r *contextRules) copyOf() *contextRules {
	c := newContextRules()
	for k, kw := range r.aliases {
		c.aliases[k] = kw
	}
	for k, names := range r.names {
		c.names[k] = append([]string(nil), names...)
	}
	return c
}

// rejectAliasChains refuses a term whose definition names a term that is an
// alias of a keyword: JSON-LD reads it as the keyword too, and the rules read
// an alias of a keyword one step only. It runs once every context the
// document can use is read, as a term may name one defined in another.
func (r *contextRules) rejectAliasChains() error {
	for _, term := range sortedKeys(r.names) {
		for _, name := range r.names[term] {
			if kw, ok := r.aliases[name]; ok && name != term {
				return fmt.Errorf("urdna2015: context term %s names %s, an alias of %s: the RDFC path reads an alias of a keyword one step only", bounded(term), bounded(name), kw)
			}
		}
	}
	return nil
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
				} else {
					r.names[term] = append(r.names[term], d)
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
				} else if ok {
					r.names[term] = append(r.names[term], id)
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
// a context is refused; an alias of @context too, in whatever scope, as
// JSON-LD 1.1 makes it an invalid keyword alias (json-gold refuses one only in
// a scope it processes, and reads the term as a property in one it does not);
// an alias of @json too, in whatever scope, as the RDFC path accepts no JSON
// literal, so such an alias has no use it signs; and a term two definitions
// alias to different keywords is refused, so each term reads as one keyword
// in whatever order the definitions are read. An alias is read one step: a
// term naming an alias of a keyword is refused (rejectAliasChains). The
// aliases read here may be more than json-gold's, as one may be in a scope
// not in use. They are used to refuse (@index,
// @direction, or @language outside a value object) by name, and to read a
// member's position (forms.go): no value is left uncounted by an alias, since
// the walk of forms reads a value object's keys and its @type only as written,
// and dataValues counts every key not written as a keyword, so an alias read
// wrong can only refuse.
func (r *contextRules) alias(term, keyword string) error {
	if keyword == "@value" {
		return fmt.Errorf("urdna2015: context term %s is an alias of @value: the RDFC path knows a value object by @value alone", bounded(term))
	}
	if keyword == "@context" {
		return fmt.Errorf("urdna2015: context term %s is an alias of @context, which JSON-LD 1.1 does not allow", bounded(term))
	}
	if keyword == "@json" {
		return fmt.Errorf("urdna2015: context term %s is an alias of @json: the RDFC path accepts no JSON literal", bounded(term))
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

// rejectLocalContexts refuses the first @context in v, at any depth, that is
// not the IRI of a context served or a list of them: a context written in
// the document (a local context), or an IRI not served. JSON-LD gives
// @context no alias, so the key written out finds every context. path is
// where v is, for the error.
func rejectLocalContexts(v any, served map[string][]byte, path *jsonPath) error {
	switch t := v.(type) {
	case []any:
		for i, x := range t {
			*path = append(*path, pathSegment{index: i})
			if err := rejectLocalContexts(x, served, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			*path = append(*path, pathSegment{key: k, index: -1})
			var err error
			if k == "@context" {
				err = rejectLocalContext(t[k], served, path)
			} else {
				err = rejectLocalContexts(t[k], served, path)
			}
			if err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	}
	return nil
}

// rejectLocalContext refuses a @context value at path that is not the IRI of
// a context served or a list of them.
func rejectLocalContext(ctx any, served map[string][]byte, path *jsonPath) error {
	list, ok := ctx.([]any)
	if !ok {
		return rejectUnservedContext(ctx, served, path)
	}
	for i, x := range list {
		*path = append(*path, pathSegment{index: i})
		if err := rejectUnservedContext(x, served, path); err != nil {
			return err
		}
		*path = (*path)[:len(*path)-1]
	}
	return nil
}

// rejectUnservedContext refuses a context at path that is not the IRI of a
// context served, naming what it is.
func rejectUnservedContext(ctx any, served map[string][]byte, path *jsonPath) error {
	switch t := ctx.(type) {
	case string:
		if _, ok := served[t]; ok {
			return nil
		}
		return fmt.Errorf("urdna2015: @context at %s names %s, a context this Canonicalizer does not serve", path.quoted(), bounded(t))
	case map[string]any:
		return fmt.Errorf("urdna2015: @context at %s is a context written in the document: this Canonicalizer reads only the contexts it serves, by their IRIs, unless WithLocalContexts opens it", path.quoted())
	case []any:
		return fmt.Errorf("urdna2015: @context at %s holds a list, not the IRI of a context this Canonicalizer serves", path.quoted())
	case bool:
		return fmt.Errorf("urdna2015: @context at %s holds a boolean, not the IRI of a context this Canonicalizer serves", path.quoted())
	case nil:
		return fmt.Errorf("urdna2015: @context at %s holds null, not the IRI of a context this Canonicalizer serves", path.quoted())
	}
	return fmt.Errorf("urdna2015: @context at %s holds a value of type %T, not the IRI of a context this Canonicalizer serves", path.quoted(), ctx)
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
