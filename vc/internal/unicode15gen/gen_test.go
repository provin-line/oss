package main

import (
	"strings"
	"testing"
)

const unicodeData = `0000;<control>;Cc;0;BN;;;;;N;NULL;;;;
0001;<control>;Cc;0;BN;;;;;N;START OF HEADING;;;;
0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;
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

func TestCategory_ReadsOneGeneralCategory(t *testing.T) {
	got, err := category(strings.NewReader(unicodeData), "Cf")
	if err != nil {
		t.Fatal(err)
	}
	want := []rng{{0x00AD, 0x00AD}, {0x200B, 0x200C}, {0xE0001, 0xE0001}}
	if !equal(got, want) {
		t.Errorf("Cf = %x, want %x", got, want)
	}
	got, err = category(strings.NewReader(unicodeData), "Co")
	if err != nil || !equal(got, []rng{{0xE000, 0xF8FF}}) {
		t.Errorf("Co (a First/Last range) = %x, %v", got, err)
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

func TestSource_WritesARangeTable(t *testing.T) {
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

func TestCategory_RefusesAFirstOrLastLineOutOfPlace(t *testing.T) {
	for name, data := range map[string]string{
		"a Last line alone":          "0003;<Private Use, Last>;Co;0;L;;;;;N;;;;;\n",
		"a First line alone":         "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n",
		"a First line, then another": "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n0002;X;Cf;0;BN;;;;;N;;;;;\n",
		"categories that differ":     "0001;<Private Use, First>;Co;0;L;;;;;N;;;;;\n0003;<Private Use, Last>;Cs;0;L;;;;;N;;;;;\n",
	} {
		if got, err := category(strings.NewReader(data), "Co"); err == nil {
			t.Errorf("%s: %x, want an error", name, got)
		}
	}
}

func TestRanges_MergesOverlappingAndAdjacentCodePoints(t *testing.T) {
	got := ranges([]rune{5, 3, 4, 4, 10, 11, 7})
	if want := []rng{{3, 5}, {7, 7}, {10, 11}}; !equal(got, want) {
		t.Errorf("ranges = %v, want %v", got, want)
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

func TestVerify_RefusesAnotherFile(t *testing.T) {
	if err := verify("PropList.txt", []byte("not the file")); err == nil {
		t.Error("a file with another SHA-256 was taken")
	}
	if err := verify("Blocks.txt", nil); err == nil {
		t.Error("a file with no pinned SHA-256 was taken")
	}
}
