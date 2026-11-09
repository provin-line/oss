package vc

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/internal/jsondepth"
)

// rdfcContextQuoteLimit bounds each document text the refusal of a context
// quotes: the path to the context, and an IRI not served.
const rdfcContextQuoteLimit = 256

// servedContextsOnly is the eddsa-rdfc-2022 canonicalizer over contexts:
// URDNA2015 over the context documents served offline, refusing first a
// document that holds any @context other than their IRIs. Every context
// definition such a document uses then comes from the served contexts, which
// this module holds, so a document cannot define a term of its own: what
// canon/urdna2015 checks a document against is fixed by the contexts vc
// serves. The canonicalizer it wraps refuses such a document too, as vc does
// not pass urdna2015.WithLocalContexts; the check here holds the rule on vc's
// path whatever that default.
func servedContextsOnly(contexts map[string][]byte) canon.Canonicalizer {
	served := make(map[string]bool, len(contexts))
	for iri := range contexts {
		served[iri] = true
	}
	return servedContexts{inner: urdna2015.NewCanonicalizer(contexts), served: served}
}

// servedContexts holds the canonicalizer it wraps in a field, not embedded,
// so every method of canon.Canonicalizer is written here: one added to the
// interface does not compile until it is, rather than reaching the inner
// canonicalizer past the check.
type servedContexts struct {
	inner  *urdna2015.Canonicalizer
	served map[string]bool
}

// Name is the inner canonicalizer's.
func (s servedContexts) Name() string { return s.inner.Name() }

// Canonicalize refuses a document holding a context not served, then
// canonicalizes it.
func (s servedContexts) Canonicalize(v any) ([]byte, error) {
	var path []string
	if err := s.walk(v, &path); err != nil {
		return nil, err
	}
	return s.inner.Canonicalize(v)
}

// walk refuses the first @context in v, at any depth, that is not the IRI of
// a served context or a list of them. JSON-LD gives @context no alias, so
// the key written out finds every context. An object's keys are read in
// order, so a document is refused for the same context each time. path is
// where v is, spelled only into an error; its length is v's depth, and an
// object or array deeper than jsondepth.Max is refused before the walk
// enters it.
func (s servedContexts) walk(v any, path *[]string) error {
	switch v.(type) {
	case []any, map[string]any:
		if len(*path) >= jsondepth.Max {
			return fmt.Errorf("vc: eddsa-rdfc-2022: %w: nesting: more than %d objects and arrays deep", urdna2015.ErrTooComplex, jsondepth.Max)
		}
	}
	switch t := v.(type) {
	case []any:
		for i, x := range t {
			*path = append(*path, strconv.Itoa(i))
			if err := s.walk(x, path); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(t)) {
			*path = append(*path, k)
			var err error
			if k == "@context" {
				err = s.context(t[k], path)
			} else {
				err = s.walk(t[k], path)
			}
			if err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	}
	return nil
}

// context refuses a @context value at path that is not a served IRI or a
// list of them.
func (s servedContexts) context(v any, path *[]string) error {
	list, isList := v.([]any)
	if !isList {
		return s.entry(v, *path)
	}
	for i, x := range list {
		if err := s.entry(x, append(*path, strconv.Itoa(i))); err != nil {
			return err
		}
	}
	return nil
}

func (s servedContexts) entry(v any, path []string) error {
	var what string
	switch t := v.(type) {
	case string:
		if s.served[t] {
			return nil
		}
		what = "the IRI " + excerpt.Quoted(t, rdfcContextQuoteLimit) + ", which it does not serve"
	case map[string]any:
		what = "a context written in the document"
	case nil:
		what = "null"
	case bool:
		what = "a boolean"
	case []any:
		what = "a list"
	case float64, json.Number:
		what = "a number"
	default:
		what = fmt.Sprintf("a value of Go type %T", v)
	}
	return fmt.Errorf("vc: eddsa-rdfc-2022 accepts as @context only the IRIs of the contexts it serves: %s at %s", what, excerpt.Quoted(pointer(path), rdfcContextQuoteLimit))
}

// pointerToken escapes a token of a JSON pointer (RFC 6901).
var pointerToken = strings.NewReplacer("~", "~0", "/", "~1")

// pointer is the JSON pointer of path.
func pointer(path []string) string {
	var b strings.Builder
	for _, tok := range path {
		b.WriteByte('/')
		b.WriteString(pointerToken.Replace(tok))
	}
	return b.String()
}
