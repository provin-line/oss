package ucd_test

import (
	"testing"
	"unicode"

	"github.com/provin-line/oss/internal/ucd"
)

// unicode15Counts is how many code points UCD 15.0.0 gives each general
// category; the seven major classes add up to every code point.
var unicode15Counts = map[string]int{
	"C": 965096, "Cc": 65, "Cf": 170, "Cn": 825345, "Co": 137468, "Cs": 2048,
	"L": 136104, "LC": 4095, "Ll": 2233, "Lm": 397, "Lo": 131612, "Lt": 31, "Lu": 1831,
	"M": 2450, "Mc": 452, "Me": 13, "Mn": 1985,
	"N": 1831, "Nd": 680, "Nl": 236, "No": 915,
	"P": 842, "Pc": 10, "Pd": 26, "Pe": 77, "Pf": 10, "Pi": 12, "Po": 628, "Ps": 79,
	"S": 7770, "Sc": 63, "Sk": 125, "Sm": 948, "So": 6634,
	"Z": 19, "Zl": 1, "Zp": 1, "Zs": 17,
}

func TestVersion_Is15(t *testing.T) {
	if ucd.Version != "15.0.0" {
		t.Errorf("Version = %q, want 15.0.0", ucd.Version)
	}
}

// Every general category Go's unicode package names has a table here, with
// as many code points as UCD 15.0.0 gives it, on any toolchain; and, where the
// toolchain's tables are Unicode 15.0.0, the same code points as them.
func TestCategory_TablesAreUnicode15(t *testing.T) {
	same := unicode.Version == "15.0.0"
	if !same {
		t.Logf("Go's unicode tables are %s: only the counts are checked", unicode.Version)
	}
	if len(unicode.Categories) != len(unicode15Counts) {
		t.Errorf("Go names %d general categories, UCD 15.0.0 %d", len(unicode.Categories), len(unicode15Counts))
	}
	for name, want := range unicode15Counts {
		pinned := ucd.Category(name)
		if pinned == nil {
			t.Errorf("%s: no table", name)
			continue
		}
		n := 0
		for r := rune(0); r <= unicode.MaxRune; r++ {
			in := unicode.Is(pinned, r)
			if in {
				n++
			}
			if same && in != unicode.Is(unicode.Categories[name], r) {
				t.Errorf("%s: U+%04X pinned %v, Go's Unicode 15.0.0 table %v", name, r, in, !in)
				break
			}
		}
		if n != want {
			t.Errorf("%s: %d code points, UCD 15.0.0 has %d", name, n, want)
		}
	}
}

// A code point added after Unicode 15.0 is unassigned here, whatever the
// toolchain carries: U+1C89 is an uppercase letter from Unicode 16.0 on.
func TestCategory_ACodePointAddedLaterIsUnassigned(t *testing.T) {
	if !unicode.Is(ucd.Category("Cn"), 0x1C89) || unicode.Is(ucd.Category("L"), 0x1C89) {
		t.Error("U+1C89 is not Cn here")
	}
}

// A name that is not the short name of a general category has no table:
// long names and aliases are the caller's to map.
func TestCategory_OnlyShortNames(t *testing.T) {
	for _, name := range []string{"", "Letter", "letter", "l", "Lu ", "Greek", "White_Space", "Any"} {
		if ucd.Category(name) != nil {
			t.Errorf("Category(%q) is a table", name)
		}
	}
}

// Every table's ranges are in order, with stride 1, and neither overlap nor
// touch, but where one is split at U+FFFF between R16 and R32; LatinOffset
// counts the R16 ranges within Latin-1.
func TestCategory_RangesAreInOrderAndApart(t *testing.T) {
	check := func(name string, tab *unicode.RangeTable) {
		last := rune(-2)
		latin := 0
		for _, r := range tab.R16 {
			if r.Stride != 1 || rune(r.Lo) > rune(r.Hi) || rune(r.Lo) <= last+1 {
				t.Errorf("%s: R16 range %04X..%04X stride %d after %04X", name, r.Lo, r.Hi, r.Stride, last)
			}
			if r.Hi <= unicode.MaxLatin1 {
				latin++
			}
			last = rune(r.Hi)
		}
		for i, r := range tab.R32 {
			split := i == 0 && last == 0xFFFF && r.Lo == 0x10000
			if r.Stride != 1 || rune(r.Lo) > rune(r.Hi) || rune(r.Lo) <= last+1 && !split {
				t.Errorf("%s: R32 range %X..%X stride %d after %X", name, r.Lo, r.Hi, r.Stride, last)
			}
			last = rune(r.Hi)
		}
		if tab.LatinOffset != latin {
			t.Errorf("%s: LatinOffset %d, want %d", name, tab.LatinOffset, latin)
		}
	}
	for name := range unicode15Counts {
		if tab := ucd.Category(name); tab != nil {
			check(name, tab)
		}
	}
	if tab := ucd.Property("White_Space"); tab != nil {
		check("White_Space", tab)
	}
}

// White_Space is UCD 15.0.0's: 25 code points, and the toolchain's where
// its tables are Unicode 15.0.0 or 17.0.0, which give it the same.
func TestProperty_WhiteSpaceIsUnicode15(t *testing.T) {
	pinned := ucd.Property("White_Space")
	if pinned == nil {
		t.Fatal("no White_Space table")
	}
	same := unicode.Version == "15.0.0" || unicode.Version == "17.0.0"
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		in := unicode.Is(pinned, r)
		if in {
			n++
		}
		if same && in != unicode.Is(unicode.White_Space, r) {
			t.Errorf("White_Space: U+%04X pinned %v, Go's Unicode %s table %v", r, in, unicode.Version, !in)
		}
	}
	if n != 25 {
		t.Errorf("White_Space: %d code points, UCD 15.0.0 has 25", n)
	}
	for _, name := range []string{"Dash", "white_space", "Lu"} {
		if ucd.Property(name) != nil {
			t.Errorf("Property(%q) is a table", name)
		}
	}
}
