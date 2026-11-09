package urdna2015

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/piprate/json-gold/ld"
)

// rejectUnspellable fails on the first term of dataset, in the order of its
// graph names, that the canonical N-Quads would not write as one unambiguous
// spelling of RDFC-1.0's canonical form of the dataset (its Appendix A). An
// IRI, wherever it sits in a quad (subject, predicate, object, graph name,
// datatype), must be valid UTF-8 and hold no character N-Quads' IRIREF
// excludes unescaped (U+0000–U+0020 and < > " { } | ^ ` \), none of which an
// RFC 3987 IRI may hold: written as it is, such a character breaks the N-Quads
// line, and a space or > ends the IRI early, so two different datasets could
// be written as the same bytes. A literal must be valid UTF-8 and hold no
// character RDFC-1.0 writes escaped and URDNA2015 — json-gold, and the frozen
// v0 wire with it — writes as it is (BS, FF, U+0000–U+0007, VT, U+000E–U+001F,
// DEL, U+FFFE, U+FFFF), so every byte signed is the RDFC-1.0 canonical form
// and no byte the v0 wire signs changes. A literal typed rdf:langString must
// carry a language tag of the N-Quads LANGTAG grammar, and no other literal
// may carry one.
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
		return fmt.Errorf("literal %s is not valid UTF-8 at byte %d, which canonical N-Quads cannot write", bounded(lit.Value), notUTF8At(lit.Value))
	}
	for i, r := range lit.Value {
		if spelledApart(r) {
			return fmt.Errorf("literal %s holds %U at byte %d, which RDFC-1.0 writes escaped and URDNA2015 (the frozen v0 wire) writes as it is", bounded(lit.Value), r, i)
		}
	}
	return nil
}

// notUTF8At is the byte at which s stops being valid UTF-8, which the quote
// of s, written as valid UTF-8, cannot show; len(s) when s is valid.
func notUTF8At(s string) int {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(s)
}

func spellableIRI(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("IRI %s is not valid UTF-8 at byte %d, which canonical N-Quads cannot write", bounded(s), notUTF8At(s))
	}
	for i, r := range s {
		if r <= 0x20 || strings.ContainsRune("<>\"{}|^`\\", r) {
			return fmt.Errorf("IRI %s holds %U at byte %d, which N-Quads' IRIREF excludes unescaped", bounded(s), r, i)
		}
	}
	return nil
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
