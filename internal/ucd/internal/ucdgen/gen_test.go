package main

import (
	"strings"
	"testing"
)

const unicodeData = `0000;<control>;Cc;0;BN;;;;;N;NULL;;;;
0001;<control>;Cc;0;BN;;;;;N;START OF HEADING;;;;
0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;
0042;LATIN CAPITAL LETTER B;Lu;0;L;;;;;N;;;;0062;
0061;LATIN SMALL LETTER A;Ll;0;L;;;;;N;;;0041;;0041
01C5;LATIN CAPITAL LETTER D WITH SMALL LETTER Z WITH CARON;Lt;0;L;<compat> 0044 017E;;;;N;LATIN LETTER CAPITAL D SMALL Z HACEK;;01C4;01C6;01C5
02B0;MODIFIER LETTER SMALL H;Lm;0;L;<super> 0068;;;;N;;;;;
00AD;SOFT HYPHEN;Cf;0;BN;;;;;N;;;;;
200B;ZERO WIDTH SPACE;Cf;0;BN;;;;;N;;;;;
200C;ZERO WIDTH NON-JOINER;Cf;0;BN;;;;;N;;;;;
E000;<Private Use, First>;Co;0;L;;;;;N;;;;;
F8FF;<Private Use, Last>;Co;0;L;;;;;N;;;;;
E0001;LANGUAGE TAG;Cf;0;BN;;;;;N;;;;;
`

const propList = `# PropList-15.0.0.txt
0009..000D    ; White_Space # Cc   [5] <control-0009>..<control-000D>
0020          ; White_Space # Zs       SPACE
002D          ; Dash # Pd       HYPHEN-MINUS
3000          ; White_Space # Zs       IDEOGRAPHIC SPACE
`

func read(t *testing.T) []string {
	t.Helper()
	gc, err := generalCategories(strings.NewReader(unicodeData))
	if err != nil {
		t.Fatal(err)
	}
	return gc
}

func TestGeneralCategories_ReadsEachCodePointsCategory(t *testing.T) {
	gc := read(t)
	for r, want := range map[rune]string{
		0x0000: "Cc", 0x0041: "Lu", 0x0061: "Ll", 0x00AD: "Cf",
		0xE000: "Co", 0xF000: "Co", 0xF8FF: "Co", 0xE0001: "Cf",
		0x0002: "Cn", 0x0043: "Cn", 0xF900: "Cn", 0x10FFFF: "Cn",
	} {
		if gc[r] != want {
			t.Errorf("U+%04X is %q, want %s", r, gc[r], want)
		}
	}
}

func TestCategoryRanges_ReadsOneGeneralCategory(t *testing.T) {
	gc := read(t)
	for name, want := range map[string][]rng{
		"Cf": {{0x00AD, 0x00AD}, {0x200B, 0x200C}, {0xE0001, 0xE0001}},
		"Co": {{0xE000, 0xF8FF}},
		"Lu": {{0x0041, 0x0042}},
	} {
		if got := categoryRanges(gc, name); !equal(got, want) {
			t.Errorf("%s = %x, want %x", name, got, want)
		}
	}
}

// A major class is its subcategories together; LC is Lu, Ll and Lt; C holds
// the unassigned code points, Cn.
func TestCategoryRanges_JoinsAMajorClass(t *testing.T) {
	gc := read(t)
	for name, want := range map[string][]rng{
		"L":  {{0x0041, 0x0042}, {0x0061, 0x0061}, {0x01C5, 0x01C5}, {0x02B0, 0x02B0}},
		"LC": {{0x0041, 0x0042}, {0x0061, 0x0061}, {0x01C5, 0x01C5}},
		"C":  {{0x0000, 0x0040}, {0x0043, 0x0060}, {0x0062, 0x01C4}, {0x01C6, 0x02AF}, {0x02B1, 0x10FFFF}},
	} {
		if got := categoryRanges(gc, name); !equal(got, want) {
			t.Errorf("%s = %x, want %x", name, got, want)
		}
	}
}

func TestCategoryNames_AreTheThirtyEightOfGo(t *testing.T) {
	if len(categoryNames) != 38 {
		t.Errorf("%d names, Go's unicode.Categories has 38", len(categoryNames))
	}
}

func TestGeneralCategories_RefusesWhatIsNotUnicodeData(t *testing.T) {
	for name, data := range map[string]string{
		"a Last line alone":          "0003;<Private Use, Last>;Co;0;L;;;;;N;;;;;\n",
		"a First line alone":         "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n",
		"a First line, then another": "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n0002;X;Cf;0;BN;;;;;N;;;;;\n",
		"categories that differ":     "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n0003;<Private Use, Last>;Cs;0;L;;;;;N;;;;;\n",
		"an unknown category":        "0041;X;Xx;0;L;;;;;N;;;;;\n",
		"a listed Cn":                "0041;X;Cn;0;L;;;;;N;;;;;\n",
		"a code point listed twice":  "0041;X;Lu;0;L;;;;;N;;;;;\n0041;X;Lu;0;L;;;;;N;;;;;\n",
		"beyond U+10FFFF":            "110000;X;Lu;0;L;;;;;N;;;;;\n",
		"not hexadecimal":            "00G1;X;Lu;0;L;;;;;N;;;;;\n",
	} {
		if _, err := generalCategories(strings.NewReader(data)); err == nil {
			t.Errorf("%s: read, want an error", name)
		}
	}
}

func TestProperty_ReadsOneProperty(t *testing.T) {
	got, err := property(strings.NewReader(propList), "White_Space")
	if err != nil {
		t.Fatal(err)
	}
	want := []rng{{0x0009, 0x000D}, {0x0020, 0x0020}, {0x3000, 0x3000}}
	if !equal(got, want) {
		t.Errorf("White_Space = %x, want %x", got, want)
	}
}

func TestTable_WritesARangeTable(t *testing.T) {
	src := table("cf", []rng{{0x00AD, 0x00AD}, {0x200B, 0x200C}, {0xE0001, 0xE0001}})
	for _, want := range []string{
		"var cf = &unicode.RangeTable{",
		"{Lo: 0x00ad, Hi: 0x00ad, Stride: 1},",
		"{Lo: 0x200b, Hi: 0x200c, Stride: 1},",
		"R32: []unicode.Range32{",
		"{Lo: 0xe0001, Hi: 0xe0001, Stride: 1},",
		"LatinOffset: 1,",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("source lacks %q:\n%s", want, src)
		}
	}
}

func TestTable_SplitsARangeAcrossUFFFF(t *testing.T) {
	src := table("x", []rng{{0xFFF0, 0x10010}})
	for _, want := range []string{"{Lo: 0xfff0, Hi: 0xffff, Stride: 1},", "{Lo: 0x10000, Hi: 0x10010, Stride: 1},", "LatinOffset: 0,"} {
		if !strings.Contains(src, want) {
			t.Errorf("source lacks %q:\n%s", want, src)
		}
	}
}

// everyCategory is a code point of each subcategory, the rest unassigned.
func everyCategory() []string {
	gc := make([]string, maxRune+1)
	for c := range gc {
		gc[c] = "Cn"
	}
	for i, cat := range subcategories {
		gc[0x100+i] = cat
	}
	return gc
}

func TestSource_WritesTheVersionAndEveryTable(t *testing.T) {
	ws, err := property(strings.NewReader(propList), "White_Space")
	if err != nil {
		t.Fatal(err)
	}
	src, err := source(everyCategory(), ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"// Code generated by internal/ucd/internal/ucdgen from UCD 15.0.0; DO NOT EDIT.",
		"package ucd",
		`const Version = "15.0.0"`,
		`"LC": categoryLC,`,
		`"Cn": categoryCn,`,
		`"White_Space": propertyWhiteSpace,`,
		"var categoryLu = &unicode.RangeTable{",
		"var propertyWhiteSpace = &unicode.RangeTable{",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("source lacks %q", want)
		}
	}
}

// A category or property with no code points is not written: the file read
// was not the UCD's.
func TestSource_RefusesAnEmptyTable(t *testing.T) {
	ws := []rng{{0x20, 0x20}}
	if _, err := source(read(t), ws); err == nil {
		t.Error("written with no code point of Cs")
	}
	if _, err := source(everyCategory(), nil); err == nil {
		t.Error("written with no code point of White_Space")
	}
}

func TestVerify_RefusesAnotherFile(t *testing.T) {
	if err := verify("PropList.txt", []byte("not the file")); err == nil {
		t.Error("a file with another SHA-256 was taken")
	}
	if err := verify("Blocks.txt", nil); err == nil {
		t.Error("a file with no pinned SHA-256 was taken")
	}
}

func equal(a, b []rng) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestProperty_RefusesWhatIsNotARange(t *testing.T) {
	for name, data := range map[string]string{
		"a range that ends before it begins": "0020..0010 ; White_Space # x\n",
		"beyond U+10FFFF":                    "110000 ; White_Space # x\n",
		"a range beyond U+10FFFF":            "10FFF0..110000 ; White_Space # x\n",
		"not hexadecimal":                    "00G0 ; White_Space # x\n",
	} {
		if _, err := property(strings.NewReader(data), "White_Space"); err == nil {
			t.Errorf("%s: read, want an error", name)
		}
	}
}
