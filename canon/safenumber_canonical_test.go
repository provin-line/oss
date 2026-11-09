package canon_test

import (
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

// What admission admits, a correctly rounded binary64 holds within
// ±(2^53-1), so the canonical form RFC 8785 writes is admitted again: a store
// that reads the canonical form back finds what the signer's gate let
// through. This checks canon/jcs's form, in both of its modes, of every table
// literal the gate admits.
func TestAdmitSafeNumbers_AdmitsTheCanonicalFormOfWhatItAdmits(t *testing.T) {
	for _, c := range literalTable(t) {
		if admitLiteral(c.Literal) == nil {
			checkCanonicalFormAdmitted(t, c.Literal)
		}
	}
}

func FuzzAdmitSafeNumbers_CanonicalFormIsAdmittedAgain(f *testing.F) {
	for _, c := range literalTable(f) {
		f.Add(c.Literal)
	}
	f.Fuzz(func(t *testing.T, lit string) {
		if admitLiteral(lit) == nil {
			checkCanonicalFormAdmitted(t, lit)
		}
	})
}

func checkCanonicalFormAdmitted(t *testing.T, lit string) {
	t.Helper()
	for name, canonicalize := range map[string]func(any) ([]byte, error){
		"RFC 8785": jcs.CanonicalizeRFC8785,
		"legacy":   jcs.Canonicalize,
	} {
		out, err := canonicalize(json.Number(lit))
		if err != nil {
			t.Errorf("%s(%.40q): %v", name, lit, err)
			continue
		}
		var v any
		if err := canon.NewStrictDecoder(out).Decode(&v); err != nil {
			t.Errorf("%s form %s of %.40q does not decode: %v", name, out, lit, err)
			continue
		}
		if err := canon.AdmitSafeNumbers(v); err != nil {
			t.Errorf("%.40q is admitted, but its %s form %s is not: %v", lit, name, out, err)
		}
	}
}
