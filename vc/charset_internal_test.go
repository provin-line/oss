package vc

import (
	"testing"
	"unicode"

	"github.com/provin-line/oss/internal/ucd"
)

// The classes credential.claim.charset refuses are the module's pinned tables
// (internal/ucd), of the Unicode version the specification pins, 15.0: each
// present, and the same code points as the toolchain's own tables where those
// are Unicode 15.0, or 17.0, in which these three classes are the same as in
// 15.0.
func TestClaimCharset_TablesAreThePinnedUnicode15(t *testing.T) {
	if ucd.Version != "15.0.0" {
		t.Fatalf("the pinned tables are Unicode %s; credential.claim.charset pins Unicode 15.0", ucd.Version)
	}
	sameClasses := unicode.Version == "15.0.0" || unicode.Version == "17.0.0"
	if !sameClasses {
		t.Logf("Go's unicode tables are %s: only the pinned tables are checked", unicode.Version)
	}
	for name, tc := range map[string]struct {
		table, pinned, goTable *unicode.RangeTable
	}{
		"Cc":          {charsetCc, ucd.Category("Cc"), unicode.Cc},
		"Cf":          {charsetCf, ucd.Category("Cf"), unicode.Cf},
		"White_Space": {charsetWhiteSpace, ucd.Property("White_Space"), unicode.White_Space},
	} {
		if tc.table == nil || tc.table != tc.pinned {
			t.Errorf("%s: not the pinned table", name)
			continue
		}
		if !sameClasses {
			continue
		}
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if in := unicode.Is(tc.table, r); in != unicode.Is(tc.goTable, r) {
				t.Errorf("%s: U+%04X pinned %v, Go's Unicode %s table %v", name, r, in, unicode.Version, !in)
				break
			}
		}
	}
}
