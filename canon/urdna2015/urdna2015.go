// Package urdna2015 implements RDF Dataset Canonicalization (URDNA2015) for
// the eddsa-rdfc-2022 cryptosuite, wrapping github.com/piprate/json-gold.
//
// JSON-LD contexts are resolved exclusively from an in-process allowlist of
// embedded documents — never the network. Any context IRI outside the
// allowlist is an error, and a non-object input (which json-gold would treat
// as a remote document URL) is rejected before it reaches the processor.
//
// Unlike JCS, which signs every member of the input bytes, RDF
// canonicalization signs the RDF dataset the input EXPANDS to — and standard
// JSON-LD processing silently discards what does not expand: undefined
// terms, relative-IRI node ids, relative-IRI type values, and numeric
// values above 2^53 lose either their presence or their precision without
// an error. On a signing path every one of those is a malleability hazard
// (bytes that ride the credential but not the signature), so Canonicalize
// fails closed on all of them; see the validation steps in Canonicalize.
// The JCS path needs none of this because it has no expansion step.
package urdna2015

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// Name is the wire identifier of this canonicalization.
const Name = "urdna2015"

// Canonicalizer normalizes JSON-LD documents to canonical N-Quads bytes using
// an offline document loader.
type Canonicalizer struct {
	contexts map[string][]byte
}

// NewCanonicalizer returns a Canonicalizer whose loader serves exactly the
// given context documents (IRI → bytes) and fails on any other IRI. The map
// and its byte slices are defensively copied, so later caller mutation cannot
// change canonical output. A context document that is not valid JSON is
// reported by Canonicalize (registration-time probing is the caller's
// responsibility — see vc.RegisterCryptosuite).
func NewCanonicalizer(contexts map[string][]byte) *Canonicalizer {
	copied := make(map[string][]byte, len(contexts))
	for iri, doc := range contexts {
		b := make([]byte, len(doc))
		copy(b, doc)
		copied[iri] = b
	}
	return &Canonicalizer{contexts: copied}
}

// Name implements canon.Canonicalizer.
func (c *Canonicalizer) Name() string { return Name }

// Canonicalize implements canon.Canonicalizer: it returns the canonical
// N-Quads (URDNA2015, application/n-quads) for v. Before normalization the
// input is validated fail-closed so that nothing JSON-LD processing would
// silently discard can reach the signing scope:
//
//  1. v must be a JSON object or an array whose every element is an object;
//     a string input is rejected (json-gold treats it as a URL to fetch),
//     and a scalar array element is rejected because expansion drops
//     free-floating scalars silently ([{…}, "rider"] would canonicalize
//     identically to [{…}]). The same rule applies to @graph entries.
//  2. No member anywhere in v may be numeric — json-gold transits numbers
//     through float64, truncating integers above 2^53, so a numeric member
//     could differ between received bytes and signed bytes. Encode numerics
//     as strings on the RDFC path.
//  3. No value anywhere in v may be null — expansion drops null members and
//     null array entries silently (JSON-LD's null-equals-omission), which
//     would let a member ride the credential outside the signature. Omit
//     the member instead.
//  4. Expansion runs in safe mode: a term no allowlisted context defines is
//     an error instead of a silent drop.
//  5. The expanded form is then checked for shapes toRDF would still drop
//     silently: @id / @type / predicate values that are not absolute IRIs
//     (or that fail json-gold's own quad-validity IRI check, mirrored via
//     ld.InvalidNode), blank-node predicates, @index members (index maps
//     emit no quads), @direction members (json-gold v0.8.0 does not
//     serialize base direction), and @language values failing json-gold's
//     language grammar (an invalid tag drops the whole literal). The
//     @language check mirrors json-gold's validity regex exactly, so
//     everything accepted here is emitted there.
//
// One drop shape is deliberately ALLOWED: a member whose value is an empty
// array ("derived_from": []) contributes zero quads, so its presence is not
// itself signed at the proof layer. That is safe for provin's only
// empty-array member because the binding lives one layer up: the signed
// source_root commits to the (empty) set cryptographically and
// VerifySourceCommitment — the chainwalk layer, not VerifyProof — recomputes
// the root over derived_from and rejects a mismatch; wire-form validation
// additionally couples the commitment fields together. JCS — the default
// suite — signs the bytes verbatim either way.
func (c *Canonicalizer) Canonicalize(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		// A JSON-LD document object.
	case []any:
		if err := requireNodeObjects(t, "(top level)"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("urdna2015: input must be a JSON object or array, got %T", v)
	}
	if err := rejectSilentDrops(v, ""); err != nil {
		return nil, err
	}

	proc := ld.NewJsonLdProcessor()
	opts := c.options()
	expanded, err := proc.Expand(v, opts)
	if err != nil {
		return nil, fmt.Errorf("urdna2015: expand: %w", err)
	}
	if err := rejectDroppableNodes(expanded); err != nil {
		return nil, err
	}

	normalized, err := proc.Normalize(expanded, opts)
	if err != nil {
		return nil, fmt.Errorf("urdna2015: normalize: %w", err)
	}
	s, ok := normalized.(string)
	if !ok {
		return nil, fmt.Errorf("urdna2015: normalize returned %T, want application/n-quads string", normalized)
	}
	return []byte(s), nil
}

// options pins every json-gold knob that could influence canonical bytes.
// A fresh value per use keeps calls independent (the processor does not own
// the options object).
func (c *Canonicalizer) options() *ld.JsonLdOptions {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"
	opts.DocumentLoader = &offlineLoader{contexts: c.contexts}
	// Safe mode turns expansion's silent drop of undefined terms into an
	// error (see the package doc for why dropping is a signing hazard).
	opts.SafeMode = true
	return opts
}

// offlineLoader serves context documents from the embedded allowlist and
// nothing else. There is deliberately no network fallback path to fail over
// to — offline is structural, not configured.
type offlineLoader struct {
	contexts map[string][]byte
}

func (l *offlineLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	doc, ok := l.contexts[u]
	if !ok {
		return nil, fmt.Errorf("urdna2015: context %q is not in the embedded allowlist (network fetch refused)", u)
	}
	// Plain unmarshal (numbers as float64), not a strict decoder: this parses
	// the TRUSTED embedded context documents, whose "@version": 1.1 members
	// json-gold compares as float64. Untrusted input never flows through here.
	var parsed any
	// decoder-hygiene-exempt: trusted embedded contexts; strictness cannot matter.
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return nil, fmt.Errorf("urdna2015: embedded context %q is not valid JSON: %w", u, err)
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: parsed}, nil
}

// requireNodeObjects fails unless every element of a node-array position
// (the top-level array, an @graph value) is a JSON object — expansion drops
// scalar entries in those positions silently (see Canonicalize step 1).
func requireNodeObjects(list []any, where string) error {
	for i, e := range list {
		if _, ok := e.(map[string]any); !ok {
			return fmt.Errorf("urdna2015: element %d of %s is %T, want a JSON object — expansion drops scalar node-array entries silently (an unsigned rider)", i, where, e)
		}
	}
	return nil
}

// rejectSilentDrops walks the raw input and fails on every value expansion
// would discard or mutate without an error: numerics (Canonicalize step 2),
// nulls (step 3), and non-object @graph entries (step 1). path is the
// JSON-pointer-ish location for the error.
func rejectSilentDrops(v any, path string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if k == "@graph" {
				if list, ok := e.([]any); ok {
					if err := requireNodeObjects(list, path+"/@graph"); err != nil {
						return err
					}
				}
			}
			if err := rejectSilentDrops(e, path+"/"+k); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range t {
			if err := rejectSilentDrops(e, fmt.Sprintf("%s/%d", path, i)); err != nil {
				return err
			}
		}
	case string, bool:
		// The value types the RDFC path canonicalizes losslessly.
	case nil:
		return fmt.Errorf("urdna2015: refusing null at %q: JSON-LD expansion drops null members and null array entries silently (an unsigned rider) — omit the member instead", path)
	default:
		// json.Number, float64, and every other scalar type land here.
		return fmt.Errorf("urdna2015: refusing value of type %T at %q: JSON numbers are rejected on the RDFC path (integers above 2^53 are silently truncated in JSON-LD processing) — encode numeric values as strings", v, path)
	}
	return nil
}

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

// rejectDroppableNodes walks an EXPANDED JSON-LD document and fails on the
// shapes toRDF discards without error even in safe mode (see Canonicalize
// step 5). After expansion every key is an absolute IRI or a keyword, so the
// walk needs no context awareness.
func rejectDroppableNodes(v any) error {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if err := rejectDroppableNodes(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range t {
			switch k {
			case "@id":
				id, ok := e.(string)
				if !ok || !validEmittedIRI(id) {
					return fmt.Errorf("urdna2015: @id %v is not a valid absolute IRI — toRDF would silently drop the node from the signing scope", e)
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
					if !ok || !validEmittedIRI(name) {
						return fmt.Errorf("urdna2015: type %v does not expand to a valid absolute IRI — toRDF would silently drop it from the signing scope", tv)
					}
				}
			case "@index":
				// Index maps are a compaction convenience: expansion keeps
				// @index but toRDF emits nothing for it.
				return fmt.Errorf("urdna2015: @index member — toRDF emits no quads for it, so it would ride the document unsigned")
			case "@direction":
				// json-gold v0.8.0 does not serialize base direction: value
				// objects differing only in @direction canonicalize
				// identically.
				return fmt.Errorf("urdna2015: @direction member — json-gold does not serialize base direction, so it would ride the document unsigned")
			case "@language":
				lang, ok := e.(string)
				if !ok || !validLanguageRegex.MatchString(lang) {
					return fmt.Errorf("urdna2015: @language %v fails the quad-validity language grammar — toRDF would silently drop the whole literal from the signing scope", e)
				}
			default:
				// A blank-node predicate is dropped by toRDF (generalized
				// RDF is off, pinned by options()); an IRI predicate failing
				// quad sanitization drops its quads too.
				if strings.HasPrefix(k, "_:") {
					return fmt.Errorf("urdna2015: blank-node predicate %q — toRDF would silently drop it from the signing scope", k)
				}
				if !ld.IsKeyword(k) && !validEmittedIRI(k) {
					return fmt.Errorf("urdna2015: predicate %q fails quad validation — toRDF would silently drop its quads from the signing scope", k)
				}
			}
			if err := rejectDroppableNodes(e); err != nil {
				return err
			}
		}
	}
	return nil
}
