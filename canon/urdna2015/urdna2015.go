// Package urdna2015 implements RDF Dataset Canonicalization (URDNA2015) for
// the eddsa-rdfc-2022 cryptosuite. github.com/piprate/json-gold expands the
// document and builds its RDF dataset; the blank nodes are labelled here,
// within a work bound (see label.go).
//
// JSON-LD contexts are resolved exclusively from an in-process allowlist of
// embedded documents — never the network. Any context IRI outside the
// allowlist is an error, and a non-object input (which json-gold would treat
// as a remote document URL) is rejected before it reaches the processor.
// Canonicalize reads a context written in the document too, holding it to
// the forms below. vc's eddsa-rdfc-2022 refuses such a document before it
// is canonicalized, accepting as @context only the IRIs of the contexts it
// serves; a program that calls this package itself gets no such refusal.
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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/piprate/json-gold/ld"

	"github.com/provin-line/oss/internal/jsondepth"
)

// Name is the wire identifier of this canonicalization.
const Name = "urdna2015"

// Error is the type of the errors this package reports by value. Canonicalize
// wraps them; match them with errors.Is.
type Error string

func (e Error) Error() string { return string(e) }

// ErrTooComplex reports a document Canonicalize refuses because canonicalizing
// it would take more work than Canonicalize allows: walking a document nested
// deeper than encoding/json decodes (each walk recurses at least once per
// level, and an exhausted goroutine stack is a fatal error), building its
// dataset (the node map of JSON-LD 1.1 Processing Algorithms and API, Node
// Map Generation, which compares each value a node's property gathers with
// those before it), writing a canonical form longer than a bound linear in
// the document's size (each quad writes its IRIs whole), or labelling its
// blank nodes (RDFC-1.0 §4.4: the algorithm "raises an error if the input
// dataset is determined to be overly complex"). Canonicalize returns it for
// no other reason, and returns no bytes with it. The error wrapping it names
// the stage ("nesting:", "node map:", "canonical form:" or "labelling:") and
// the bound, for a person reading it; neither that text nor the bounds' values are part of
// this contract, and they may change. errors.Is finds ErrTooComplex for every
// stage; the contract does not tell the stages apart.
const ErrTooComplex Error = "urdna2015: dataset too complex to canonicalize"

// Canonicalizer normalizes JSON-LD documents to canonical N-Quads bytes using
// an offline document loader.
type Canonicalizer struct {
	contexts map[string][]byte

	served *servedRules
}

// servedRules is what the served contexts define (conserve.go), read once,
// behind a pointer so a Canonicalizer copies as a value.
type servedRules struct {
	once  sync.Once
	rules *contextRules
	err   error
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
	return &Canonicalizer{contexts: copied, served: &servedRules{}}
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
//     emit no quads), @direction members (json-gold does not
//     serialize base direction), and @language values failing json-gold's
//     language grammar (an invalid tag drops the whole literal). The
//     @language check mirrors json-gold's validity regex exactly, so
//     everything accepted here is emitted there.
//  6. The dataset is then checked for terms the canonical N-Quads would
//     not write as one unambiguous spelling of RDFC-1.0's canonical form of
//     the dataset (its Appendix A). An IRI, wherever it sits in a quad
//     (subject, predicate, object, graph name, datatype), must be valid
//     UTF-8 and hold no character N-Quads' IRIREF excludes unescaped
//     (U+0000–U+0020 and < > " { } | ^ ` \), none of which an RFC 3987 IRI
//     may hold: written as it is, such a character breaks the N-Quads line,
//     and a space or > ends the IRI early, so two different datasets could
//     be written as the same bytes. A literal must be valid UTF-8 and hold
//     no character RDFC-1.0 writes escaped and URDNA2015 — json-gold, and
//     the frozen v0 wire with it — writes as it is (BS, FF, U+0000–U+0007,
//     VT, U+000E–U+001F, DEL, U+FFFE, U+FFFF), so every byte signed is the
//     RDFC-1.0 canonical form and no byte the v0 wire signs changes. A
//     literal typed rdf:langString must carry a language tag of the N-Quads
//     LANGTAG grammar, and no other literal may carry one.
//  7. Above all, the document's values are counted through each stage
//     (conserve.go), so a value JSON-LD processing would leave out is refused
//     whatever the form that loses it. The document must use only forms where
//     a value stays one value: no member named "" outside a context; no
//     @index, @direction, JSON literal or blank node label; no @set or
//     framing keyword written in the document;
//     @language only in a value object, and a language tag, there or in a
//     context, of ASCII letters, digits and hyphens; a value object's keys
//     written as @value, @type and @language; at most one datatype, and on a
//     boolean none but xsd:boolean; no RDF collection vocabulary written out
//     (rdf:first or rdf:rest as a property, rdf:nil as an IRI), so a list
//     comes only from @list, and nothing beside @list in a list object, nor an
//     item of a list that JSON-LD could not expand; no context term with a map
//     container, no alias of @value, no term aliasing two keywords, no @vocab
//     beginning with @, and no @base. Its values must all reach the expanded
//     form; there, each value must belong to a node's property, each node
//     object must add a quad, and no node's property may hold one RDF term
//     twice; and the dataset must hold exactly the quads those values make.
//     What is signed is the dataset, so spellings JSON-LD gives one RDF term
//     are signed as that term: an IRI written as a term, a compact IRI or in
//     full; a language tag in any ASCII case; a string with xsd:string written
//     or not; a boolean written as true or false, or as the string of its name
//     typed xsd:boolean. The values of a property outside a list are signed as
//     a set, in no order, so one written twice is refused (a node written out
//     in full in two places, or a type repeated): write a node once and refer
//     to it elsewhere by its @id. A context's own text is not signed, nor
//     which context a document names: a term the document does not use adds
//     nothing to the dataset.
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
//
// A document nested more than 10,000 objects and arrays deep, deeper than
// encoding/json decodes, is refused with an error wrapping
// ErrTooComplex before any walk of Canonicalize recurses into it: each walk,
// and json-gold's, recurses at least once per level, and a goroutine stack
// exhausted is a fatal error.
//
// json-gold asserts the types of values it has not checked, and recovers
// nothing: where it panics on a document, in expansion or in building the
// dataset, Canonicalize returns an error instead (see jsongold.go).
//
// Building the dataset is bounded too (see nodemap.go): json-gold compares
// each value a node's property gathers with those before it, so before it
// runs, a document whose node map would compare more pairs of values than a
// bound linear in its values is refused with an error wrapping
// ErrTooComplex.
//
// The canonical form is bounded too (see size.go): it writes each quad's
// IRIs whole, so once the dataset is built and before its blank nodes are
// labelled, a dataset whose canonical form would be longer than a bound
// linear in the document's size is refused with an error wrapping
// ErrTooComplex.
//
// The blank nodes are labelled within a work bound, as RDFC-1.0 §4.4.3
// requires (see label.go): a dataset whose blank nodes are so alike that
// labelling them would take more than a fixed number of steps and a fixed
// number per quad is refused with an error wrapping ErrTooComplex, so
// labelling never costs more than that many steps of about the same time
// each.
func (c *Canonicalizer) Canonicalize(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		// A JSON-LD document object.
	case []any:
		if err := requireNodeObjects(t, func() string { return "(top level)" }); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("urdna2015: input must be a JSON object or array, got %T", v)
	}
	if !jsondepth.Within(v) {
		return nil, fmt.Errorf("%w: nesting: more than %d objects and arrays deep", ErrTooComplex, jsondepth.Max)
	}
	if err := rejectSilentDrops(v, new(jsonPath), false); err != nil {
		return nil, err
	}
	in := documentBytes(v)
	values, err := c.dataValues(v)
	if err != nil {
		return nil, err
	}

	proc := ld.NewJsonLdProcessor()
	opts := c.options()
	var expanded []any
	if err := fromJSONGold(func() (err error) {
		expanded, err = proc.Expand(v, opts)
		return err
	}); err != nil {
		return nil, fmt.Errorf("urdna2015: expand: %w", err)
	}
	if err := rejectDroppableNodes(expanded); err != nil {
		return nil, err
	}
	if n := expandedValues(expanded); n != values {
		return nil, fmt.Errorf("urdna2015: the document holds %d values, its expanded form %d: JSON-LD drops the others, so they would ride the document unsigned", values, n)
	}
	w := newNodeMapWork()
	w.walk(expanded)
	if err := w.bound(); err != nil {
		return nil, err
	}
	if err := w.conserved(); err != nil {
		return nil, err
	}

	dataset, err := datasetOf(proc, expanded, opts)
	if err != nil {
		return nil, err
	}
	if err := w.holds(dataset); err != nil {
		return nil, err
	}
	if err := boundCanonicalSize(dataset, in); err != nil {
		return nil, err
	}
	if err := rejectUnspellable(dataset); err != nil {
		return nil, err
	}
	s, err := canonicalNQuads(dataset)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// dataValues reads the contexts the document can use, the served ones and its
// own, refusing one with a map container, and counts the document's values
// (conserve.go).
func (c *Canonicalizer) dataValues(v any) (int64, error) {
	served := c.served
	if served == nil {
		served = &servedRules{}
	}
	served.once.Do(func() {
		served.rules = newContextRules()
		served.err = served.rules.readServed(c.contexts)
	})
	if served.err != nil {
		return 0, served.err
	}
	rules := newContextRules()
	for k, kw := range served.rules.aliases {
		rules.aliases[k] = kw
	}
	if err := rules.readDocument(v); err != nil {
		return 0, err
	}
	return rules.dataValues(v, new(jsonPath))
}

// datasetOf builds the RDF dataset of an expanded document as json-gold's
// Normalize builds it, with the options it passes to toRDF.
func datasetOf(proc *ld.JsonLdProcessor, expanded any, opts *ld.JsonLdOptions) (*ld.RDFDataset, error) {
	toRDF := ld.NewJsonLdOptions(opts.Base)
	toRDF.ProcessingMode = opts.ProcessingMode
	toRDF.Format = ""
	toRDF.DocumentLoader = opts.DocumentLoader
	var rdf any
	if err := fromJSONGold(func() (err error) {
		rdf, err = proc.ToRDF(expanded, toRDF)
		return err
	}); err != nil {
		return nil, fmt.Errorf("urdna2015: normalize: %w", err)
	}
	dataset, ok := rdf.(*ld.RDFDataset)
	if !ok {
		return nil, fmt.Errorf("urdna2015: toRDF returned %T, want an RDF dataset", rdf)
	}
	return dataset, nil
}

// options pins every json-gold knob that could influence the expanded
// document and its dataset. A fresh value per use keeps calls independent
// (the processor does not own the options object).
func (c *Canonicalizer) options() *ld.JsonLdOptions {
	opts := ld.NewJsonLdOptions("")
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
		return nil, fmt.Errorf("urdna2015: context %s is not in the embedded allowlist (network fetch refused)", bounded(u))
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
func requireNodeObjects(list []any, where func() string) error {
	for i, e := range list {
		if _, ok := e.(map[string]any); !ok {
			return fmt.Errorf("urdna2015: element %d of %s is %T, want a JSON object — expansion drops scalar node-array entries silently (an unsigned rider)", i, where(), e)
		}
	}
	return nil
}

// jsonPath is the location of a value in the input, one segment a level: an
// array element's index (index ≥ 0), or an object member's key (index −1).
// The walk pushes and pops one shared stack and spells it only into an error,
// so walking a document costs no more than its size, however deep or wide.
type jsonPath []pathSegment

type pathSegment struct {
	key   string
	index int
}

func (p *jsonPath) String() string {
	var b strings.Builder
	for _, s := range *p {
		b.WriteByte('/')
		if s.index >= 0 {
			b.WriteString(strconv.Itoa(s.index))
		} else {
			b.WriteString(s.key)
		}
	}
	return b.String()
}

// rejectSilentDrops walks the raw input and fails on every value expansion
// would discard or mutate without an error: numerics (Canonicalize step 2),
// nulls (step 3), non-object @graph entries (step 1), and a member named ""
// outside a context (step 7). path is the JSON-pointer-ish location of v, for
// the error; inContext is whether v is in a context (a member named @context
// is always one, as JSON-LD gives @context no alias).
func rejectSilentDrops(v any, path *jsonPath, inContext bool) error {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[""]; ok && !inContext {
			return fmt.Errorf("urdna2015: a member named \"\" at %q: JSON-LD gives the empty name no meaning, so the RDFC path does not read it", path.String())
		}
		for _, k := range sortedKeys(t) {
			e := t[k]
			*path = append(*path, pathSegment{key: k, index: -1})
			if k == "@graph" {
				if list, ok := e.([]any); ok {
					if err := requireNodeObjects(list, path.String); err != nil {
						return err
					}
				}
			}
			if err := rejectSilentDrops(e, path, inContext || k == "@context"); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case []any:
		for i, e := range t {
			*path = append(*path, pathSegment{index: i})
			if err := rejectSilentDrops(e, path, inContext); err != nil {
				return err
			}
			*path = (*path)[:len(*path)-1]
		}
	case string, bool:
		// The value types the RDFC path canonicalizes losslessly.
	case nil:
		return fmt.Errorf("urdna2015: refusing null at %q: JSON-LD expansion drops null members and null array entries silently (an unsigned rider) — omit the member instead", path.String())
	default:
		// json.Number, float64, and every other scalar type land here.
		return fmt.Errorf("urdna2015: refusing value of type %T at %q: JSON numbers are rejected on the RDFC path (integers above 2^53 are silently truncated in JSON-LD processing) — encode numeric values as strings", v, path.String())
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

// rejectUnspellable fails on the first term of dataset, in the order of its
// graph names, that the canonical N-Quads would not write as one unambiguous
// spelling of the RDFC-1.0 canonical form (see Canonicalize step 6).
func rejectUnspellable(dataset *ld.RDFDataset) error {
	for _, name := range sortedKeys(dataset.Graphs) {
		if name != "@default" && !strings.HasPrefix(name, "_:") {
			if err := spellableIRI(name); err != nil {
				return fmt.Errorf("urdna2015: graph name: %w", err)
			}
		}
		for _, q := range dataset.Graphs[name] {
			for _, n := range []ld.Node{q.Subject, q.Predicate, q.Object, q.Graph} {
				if err := spellableNode(n); err != nil {
					return fmt.Errorf("urdna2015: quad of predicate %s: %w", bounded(q.Predicate.GetValue()), err)
				}
			}
		}
	}
	return nil
}

func spellableNode(n ld.Node) error {
	switch {
	case n == nil, ld.IsBlankNode(n):
		// A blank node is written with its canonical label.
		return nil
	case ld.IsIRI(n):
		return spellableIRI(n.GetValue())
	}
	lit, ok := n.(ld.Literal)
	if !ok {
		return fmt.Errorf("dataset node of type %T", n)
	}
	if err := spellableIRI(lit.Datatype); err != nil {
		return err
	}
	if lit.Datatype == ld.RDFLangString {
		if !validLanguageRegex.MatchString(lit.Language) {
			return fmt.Errorf("literal typed rdf:langString has language tag %s, which is not of the N-Quads LANGTAG grammar", bounded(lit.Language))
		}
	} else if lit.Language != "" {
		return fmt.Errorf("literal typed %s carries language tag %s", bounded(lit.Datatype), bounded(lit.Language))
	}
	if !utf8.ValidString(lit.Value) {
		return fmt.Errorf("literal %s is not valid UTF-8, which canonical N-Quads cannot write", bounded(lit.Value))
	}
	for i, r := range lit.Value {
		if spelledApart(r) {
			return fmt.Errorf("literal %s holds %U at byte %d, which RDFC-1.0 writes escaped and URDNA2015 (the frozen v0 wire) writes as it is", bounded(lit.Value), r, i)
		}
	}
	return nil
}

func spellableIRI(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("IRI %s is not valid UTF-8, which canonical N-Quads cannot write", bounded(s))
	}
	for i, r := range s {
		if r <= 0x20 || strings.ContainsRune("<>\"{}|^`\\", r) {
			return fmt.Errorf("IRI %s holds %U at byte %d, which N-Quads' IRIREF excludes unescaped", bounded(s), r, i)
		}
	}
	return nil
}

// bounded quotes at most the first 32 bytes of s, so an error never carries a
// whole literal.
func bounded(s string) string {
	const max = 32
	if len(s) <= max {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q…", s[:max])
}

// spelledApart reports whether RDFC-1.0 Appendix A and URDNA2015 write r
// differently in a literal: RDFC-1.0 writes BS and FF as ECHAR, and as UCHAR
// the other C0 controls but HT, LF and CR, DEL, and the characters XML 1.1's
// Char excludes (U+0000, the C0 branch here; U+FFFE and U+FFFF; surrogates,
// which valid UTF-8 cannot hold); URDNA2015 writes all of them as they are.
// Both escape HT, LF, CR, the quotation mark and the backslash alike.
func spelledApart(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	case 0x7F, 0xFFFE, 0xFFFF:
		return true
	}
	return r < 0x20
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
// (dataValues), so this is reached through an alias the context rules do
// not read.
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

// rejectDroppableNodes walks an EXPANDED JSON-LD document and fails on the
// shapes toRDF discards without error even in safe mode (see Canonicalize
// step 5), and on the RDF collection vocabulary written out (rdf:first and
// rdf:rest as properties, rdf:nil as an IRI): it would be signed as the list
// @list makes, which a JSON reader does not see, so a list comes only from
// @list. After expansion every key is an absolute IRI or a keyword, so the
// walk needs no context awareness.
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
