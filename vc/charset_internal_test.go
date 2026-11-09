package vc

import (
	"testing"
	"unicode"
)

// The pinned tables are UCD 15.0.0's: as many code points as it gives each
// class, on any toolchain; and the same code points as the toolchain's own
// tables where those are Unicode 15.0, or 17.0, in which these three classes
// are the same as in 15.0.
func TestClaimCharset_TablesAreUnicode15(t *testing.T) {
	sameClasses := unicode.Version == "15.0.0" || unicode.Version == "17.0.0"
	if !sameClasses {
		t.Logf("Go's unicode tables are %s: only the counts are checked", unicode.Version)
	}
	for name, tc := range map[string]struct {
		pinned, goTable *unicode.RangeTable
		count           int
	}{
		"Cc":          {unicode15Cc, unicode.Cc, 65},
		"Cf":          {unicode15Cf, unicode.Cf, 170},
		"White_Space": {unicode15WhiteSpace, unicode.White_Space, 25},
	} {
		n := 0
		for r := rune(0); r <= unicode.MaxRune; r++ {
			in := unicode.Is(tc.pinned, r)
			if in {
				n++
			}
			if sameClasses && in != unicode.Is(tc.goTable, r) {
				t.Errorf("%s: U+%04X pinned %v, Go's Unicode %s table %v", name, r, in, unicode.Version, !in)
			}
		}
		if n != tc.count {
			t.Errorf("%s: %d code points, UCD 15.0.0 has %d", name, n, tc.count)
		}
	}
}
