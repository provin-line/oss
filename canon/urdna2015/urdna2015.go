package urdna2015

import (
	"fmt"
	"sync"

	"github.com/piprate/json-gold/ld"

	"github.com/provin-line/oss/internal/excerpt"
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

// servedRules is what the served contexts define (contexts.go), read once,
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
// N-Quads (URDNA2015, application/n-quads) for v, or refuses v. What it signs
// is the RDF dataset v expands to, so before JSON-LD processing could lose
// it, Canonicalize refuses every form whose value or shape the dataset would
// not hold; the package doc lists them, each with the check that refuses it.
// The stages run in this order: the input's grammar (input.go); the context
// rules (contexts.go); the document's forms (forms.go); the count of its
// values (conserve.go); expansion (jsongold.go); the expanded form
// (expanded.go) and its count of values; the node map (nodemap.go); the
// dataset, its quads, its size and its spelling (jsongold.go, nodemap.go,
// size.go, dataset.go); and the labelling of its blank nodes (label.go).
//
// Each bound — nesting, the node map's work, the canonical form's length,
// the labelling's work — refuses with an error wrapping ErrTooComplex. Which
// stage refuses a document with more than one fault is not promised.
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
		return nil, fmt.Errorf("urdna2015: expand: %w", excerpt.OfError(err, goldErrorQuoteLimit))
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
// own (contexts.go), refuses a form of the document the dataset would not
// hold (forms.go), and counts the document's values (conserve.go).
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
	rules := served.rules.copyOf()
	if err := rules.readDocument(v); err != nil {
		return 0, err
	}
	if err := rules.rejectAliasChains(); err != nil {
		return 0, err
	}
	if err := rules.rejectUnsignedForms(v, atNode, new(jsonPath)); err != nil {
		return 0, err
	}
	n, err := rules.dataValues(v, new(jsonPath))
	if err != nil {
		return 0, err
	}
	return n, nil
}
