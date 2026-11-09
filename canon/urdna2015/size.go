package urdna2015

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// The canonical form writes each quad's IRIs whole, so its length grows with
// the quads times the IRIs they name, not with the document: a document that
// names one long IRI from many quads (their subject, the predicate of a term
// its own context defines, their graph) has a canonical form many times its
// own size, which is written, and hashed, before a proof's signature is
// checked.
//
// boundCanonicalSize refuses, once the dataset is built and before its blank
// nodes are labelled, a dataset whose canonical form, each blank node's label
// counted at its longest (canonicalSize), would be longer than canonicalBase
// bytes and canonicalPerDocumentByte per byte of the document. A form within
// the bound only once its labels are written may be refused: the labels are
// counted before they are given. To hash a blank node, labelling writes
// each quad naming it whole once, so a quad at most three times (once for
// each blank node it names), and a blank graph's quads once more; otherwise
// it hashes predicates, which its own work bound counts. So this bound also
// bounds what labelling writes, at a few times the form.
//
// The bound comes once the dataset is built, so it does not bound the work
// before that:
//
//   - json-gold's node map and ToRDF look up each value's subject, property
//     and graph, and each quad's IRIs, by their whole strings, and ToRDF
//     scans a subject's @id again at each of its properties: time in the
//     values times those strings' lengths, at the speed of hashing or
//     scanning memory (refusing a document of 1 MiB whose quads name an IRI
//     of 512 KB takes about 0.5 s, measured).
//   - Expanding the document lengthens its keys and strings by what its own
//     contexts define (WithLocalContexts). json-gold writes a new string at
//     each use of a prefix (a compact IRI) and of @vocab, so a long one used
//     many times costs memory in the uses times its length: with an @vocab of
//     half its size, a document of 250 KB made it allocate about 2.7 GB, and
//     with one of about a third, a document of 1 MiB about 37 GB (urn: IRIs;
//     darwin/arm64, measured). json-gold's bound on an IRI's length, 2,083
//     characters, holds only for http and https IRIs, and is applied to the
//     expanded form (rejectDroppableNodes mirrors it), after the expansion has
//     allocated it; an IRI of another scheme, such as urn:, has no bound. A
//     context setting @base is refused as it is read (contextRules.read).
//   - A long term IRI, a datatype a term's @type gives its values, and a
//     language a context gives them are shared but read again at each use,
//     in time in the uses times their length: with a default language of
//     half its size, a document of 250 KB took about 18 s, and one of 1 MiB
//     more than 150 s (darwin/arm64, measured).

// canonicalBase and canonicalPerDocumentByte bound the length of the
// canonical form: 1 MiB, and 32 bytes per byte of the document as JSON
// (documentBytes).
//
// The values are measured. Ordinary credentials take at most 3% of the bound
// (TestCanonicalSize_OrdinaryDocumentsStayWellWithinTheBound):
//
//	document                                         document  canonical  share
//	W3C vc-di-eddsa Example 8                             462       1080  0.10%
//	a list of 40 identical strings                        577       6174  0.58%
//	50 identical line items, each with an anonymous price  3130      17055  1.48%
//	200 identical anonymous tags                         3029      28810  2.52%
//
// Large documents of the node map's shapes (1,000 values each) have canonical
// forms of at most about 12 times their size (12.02, a list of short strings,
// each item two quads); at most half of the 32 per byte
// (TestCanonicalSize_LargeDocumentsStayWithinHalfThePerByteBound). A document
// of 1 MiB may have a canonical form of 33 MiB.
const (
	canonicalBase            = 1 << 20
	canonicalPerDocumentByte = 32
)

// canonicalLimit is the bound on the canonical form of a document of
// documentBytes bytes.
func canonicalLimit(documentBytes int64) int64 {
	return canonicalBase + canonicalPerDocumentByte*documentBytes
}

// boundCanonicalSize refuses, with an error wrapping ErrTooComplex, a dataset
// whose canonical form would be longer than the bound for a document of
// documentBytes bytes.
func boundCanonicalSize(dataset *ld.RDFDataset, documentBytes int64) error {
	if limit := canonicalLimit(documentBytes); canonicalSize(dataset) > limit {
		return fmt.Errorf("%w: canonical form: more than %d bytes, for a document of %d bytes", ErrTooComplex, limit, documentBytes)
	}
	return nil
}

// documentBytes is the length of v written as compact JSON, each string
// counted as it is, before JSON escapes it. Canonicalize gives it only what
// rejectSilentDrops admits: objects, arrays, strings and booleans.
func documentBytes(v any) int64 {
	switch t := v.(type) {
	case map[string]any:
		n := int64(2 + max(len(t)-1, 0))
		for k, x := range t {
			n += int64(len(k)) + 3 + documentBytes(x)
		}
		return n
	case []any:
		n := int64(2 + max(len(t)-1, 0))
		for _, x := range t {
			n += documentBytes(x)
		}
		return n
	case string:
		return int64(len(t)) + 2
	case bool:
		if t {
			return 4
		}
		return 5
	}
	return 0
}

// canonicalSize is the length of the canonical form of a dataset datasetOf
// builds (each quad listed under the graph it names) as nquad writes it, each
// blank node's label counted at its longest: the labels are _:c14n0,
// _:c14n1 ..., one per blank node, and a quad names at most three and a
// graph one. It counts an IRI by its length, without reading it, so its time
// is in the graphs and the quads, and the literal values' lengths, not in the
// IRIs they name: nquad escapes \ " and the
// newline, return and tab characters, and rejectUnspellable, which reads the
// IRIs once the form is known to be within the bound, refuses an IRI holding
// any of them (it refuses \ " and every character up to space). A literal's
// value is read, to count its escapes; each value is one of the document's.
func canonicalSize(dataset *ld.RDFDataset) int64 {
	quads := 0
	for _, qs := range dataset.Graphs {
		quads += len(qs)
	}
	label := int64(len("_:c14n") + len(strconv.Itoa(3*quads+len(dataset.Graphs))))
	node := func(n ld.Node) int64 {
		switch {
		case ld.IsIRI(n):
			return 2 + int64(len(n.GetValue()))
		case ld.IsBlankNode(n):
			return label
		}
		lit, ok := n.(ld.Literal)
		if !ok {
			return 0
		}
		size := 2 + escapedLen(lit.GetValue())
		if lit.Datatype == ld.RDFLangString {
			size += 1 + int64(len(lit.Language))
		} else if lit.Datatype != ld.XSDString {
			size += 4 + int64(len(lit.Datatype))
		}
		return size
	}
	var n int64
	for name, qs := range dataset.Graphs {
		var graph int64
		switch {
		case name == "@default":
		case strings.HasPrefix(name, "_:"):
			graph = 1 + label
		default:
			graph = 3 + int64(len(name))
		}
		for _, q := range qs {
			n += node(q.Subject) + 1 + node(q.Predicate) + 1 + node(q.Object) + graph + 3
		}
	}
	return n
}

// escapedLen is the length of escapeNQuads(s), without writing it.
func escapedLen(s string) int64 {
	n := int64(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"', '\n', '\r', '\t':
			n++
		}
	}
	return n
}
