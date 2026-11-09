package urdna2015

import (
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"

	"github.com/provin-line/oss/internal/excerpt"
)

// panicQuoteLimit bounds the text of a json-gold panic that an error quotes.
const panicQuoteLimit = 128

// fromJSONGold returns what call, a call into json-gold, returns, or an error
// for a panic of it. json-gold asserts the types of values it has not checked,
// and recovers nothing, so a document that fails such an assertion would end
// the goroutine, and the program with it, of a caller canonicalizing what it
// received. Only json-gold's calls run here, with the loader json-gold calls
// back for a context: a panic of the rest of this package's code is not
// caught. Recovering leaves nothing behind: json-gold builds its state
// for each call and keeps none between calls but patterns it only reads, and
// the loader parses a new document for each context it loads.
//
// A call that does not return is a panic whatever recover reports, so a panic
// with a nil value is an error under every GODEBUG setting.
func fromJSONGold(call func() error) (err error) {
	returned := false
	defer func() {
		if returned {
			return
		}
		p := recover()
		err = fmt.Errorf("json-gold panicked: %s", excerpt.Quoted(excerpt.ErrorText(panicValue{p}), panicQuoteLimit))
	}()
	err = call()
	returned = true
	return err
}

// panicValue is the value of a panic as an error, so that excerpt.ErrorText
// takes its text without panicking where its methods do.
type panicValue struct{ value any }

func (p panicValue) Error() string {
	if err, ok := p.value.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(p.value)
}

// goldErrorQuoteLimit bounds the text of a json-gold error a refusal quotes:
// json-gold writes into its error the value it refuses, which a document's own
// context makes as long as it likes. The error is wrapped whole.
const goldErrorQuoteLimit = 256

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
		return nil, fmt.Errorf("urdna2015: normalize: %w", excerpt.OfError(err, goldErrorQuoteLimit))
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
