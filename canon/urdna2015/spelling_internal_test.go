package urdna2015

import (
	"testing"

	"github.com/piprate/json-gold/ld"
)

// rejectUnspellable refuses every character an IRIREF cannot hold unescaped,
// control characters included, on the dataset alone: Canonicalize's earlier
// stages refuse control characters before it, so only a dataset built here
// reaches this check with one.
func TestRejectUnspellable_RefusesEveryCharacterIRIREFExcludes(t *testing.T) {
	iri := func(s string) ld.Node { return ld.NewIRI(s) }
	lit := ld.NewLiteral("v", ld.XSDString, "")
	for r := rune(0); r <= 0x20; r++ {
		s := "urn:example:x" + string(r)
		for place, ds := range map[string]*ld.RDFDataset{
			"subject":   dataset("@default", ld.NewQuad(iri(s), iri("urn:example:p"), lit, "")),
			"predicate": dataset("@default", ld.NewQuad(iri("urn:example:s"), iri(s), lit, "")),
			"object":    dataset("@default", ld.NewQuad(iri("urn:example:s"), iri("urn:example:p"), iri(s), "")),
			"datatype":  dataset("@default", ld.NewQuad(iri("urn:example:s"), iri("urn:example:p"), ld.NewLiteral("v", s, ""), "")),
			"graph":     dataset(s, ld.NewQuad(iri("urn:example:s"), iri("urn:example:p"), lit, s)),
		} {
			if err := rejectUnspellable(ds); err == nil {
				t.Errorf("%s IRI holding %U: want error", place, r)
			}
		}
	}
}

func dataset(graph string, q *ld.Quad) *ld.RDFDataset {
	ds := ld.NewRDFDataset()
	ds.Graphs = map[string][]*ld.Quad{graph: {q}}
	return ds
}
