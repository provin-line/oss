package schemadoc

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"

	"github.com/provin-line/oss/internal/ucd"
)

// The scan takes each long name and alias of a general category as ECMA-262
// spells it, as the category its short name names (the UCD's aliases agree):
// the same expression for Go to read, alone, negated and in classes, counted
// as the same ranges.
func TestPrescan_AcceptsCategoryAliases(t *testing.T) {
	if len(categoryAliases) != 42 {
		t.Fatalf("%d aliases, ES2020's table has 42", len(categoryAliases))
	}
	for name, short := range categoryAliases {
		if ucd.Category(short) == nil {
			t.Fatalf("%s names %s, which has no pinned table", name, short)
		}
		if got := unicode.CategoryAliases[name]; got != short {
			t.Errorf("the UCD's aliases, as Go carries them, read %s as %q, ES2020 as %s", name, got, short)
		}
		for _, form := range []string{`\p{%s}`, `\P{%s}`, `[^\p{%s}]`, `[\P{%s}a-z]`} {
			expr := fmt.Sprintf(form, name)
			long, _, err := prescan(expr)
			if err != nil {
				t.Errorf("%s refused: %v", expr, err)
				continue
			}
			brief, _, err := prescan(fmt.Sprintf(form, short))
			if err != nil {
				t.Fatal(err)
			}
			if long != brief {
				t.Errorf("%s is written out otherwise than %s", expr, fmt.Sprintf(form, short))
			}
			if _, err := syntax.Parse(long, syntax.Perl); err != nil {
				t.Errorf("Go does not read %s written out: %v", expr, err)
			}
		}
		if a, s := unicodeClassRanges(name), unicodeClassRanges(short); a != s {
			t.Errorf("%s counts %d ranges, %s %d", name, a, short, s)
		}
	}
}

// A name spelled otherwise than ECMA-262 spells it is refused, though Go's
// parser reads names loosely: ECMA-262 does not.
func TestPrescan_RefusesLooseCategoryNames(t *testing.T) {
	for _, name := range []string{
		"letter", "LETTER", "Uppercase Letter", "Uppercase-Letter", "Upper_case_Letter",
		" Letter", "Letter ", "decimal_number", "Digit", "PUNCT",
	} {
		if _, _, err := prescan(`\p{` + name + `}`); err == nil {
			t.Errorf(`\p{%s} accepted`, name)
		}
	}
}

// Properties other than a general category, and a category named with its
// property's name, are refused (Go reads some of them; this dialect does not).
func TestPrescan_RefusesOtherPropertyForms(t *testing.T) {
	for _, expr := range []string{
		`\p{gc=L}`, `\p{General_Category=Letter}`, `\p{General_Category=L}`,
		`\p{Any}`, `\p{ASCII}`, `\p{Assigned}`, `\p{Greek}`, `\p{Script=Greek}`, `\p{sc=Grek}`,
	} {
		if _, _, err := prescan(expr); err == nil {
			t.Errorf("%s accepted", expr)
		}
	}
}

// A long name counts against the bound on Unicode classes as its short name
// does: the same number of repeats is refused.
func TestPrescan_BoundsCategoryAliasesAsTheirShortNames(t *testing.T) {
	n := maxPatternSize/unicodeClassRanges("L") + 1
	for _, name := range []string{"L", "Letter"} {
		if _, _, err := prescan(strings.Repeat(`\p{`+name+`}`, n-1)); err != nil {
			t.Errorf("%d of %s refused: %v", n-1, name, err)
		}
		if _, _, err := prescan(strings.Repeat(`\p{`+name+`}`, n)); err == nil {
			t.Errorf("%d of %s accepted", n, name)
		}
	}
}

// A general category holds the code points UCD 15.0.0 gives it, whatever
// Unicode version the toolchain carries: U+1C89, an uppercase letter from
// Unicode 16.0 on, is unassigned here, in every form a category takes.
func TestCompileRegexp_ReadsCategoriesAsUnicode15(t *testing.T) {
	for expr, want := range map[string]bool{
		`^\p{Cn}$`: true, `^\p{C}$`: true, `^\p{Unassigned}$`: true, `^\p{L}$`: false, `^\p{Lu}$`: false,
		`^\P{L}$`: true, `^[\p{L}]$`: false, `^[^\p{L}]$`: true, `^[\P{Cn}a]$`: false, `^[^\P{Cn}]$`: true,
	} {
		re, err := compileRegexpWithin(expr, nil)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if got := re.MatchString("Ᲊ"); got != want {
			t.Errorf("%s matches U+1C89: %v, want %v (Unicode 15.0.0)", expr, got, want)
		}
	}
}

// Each form a category takes, alone, negated, in a class and in a negated
// class, by its short name or a long one, matches the code points of the
// pinned table and no others: at each end of each of its ranges, on either
// side, and at every 97th code point. The categories include those holding
// a character a class reads otherwise (- ^ [ ] \) and the control
// characters; a class's other members (\d \S \W \s, as Go reads them, and
// characters and ranges) and a second category join them.
func TestCompileRegexp_MatchesThePinnedTables(t *testing.T) {
	digit := func(r rune) bool { return '0' <= r && r <= '9' }
	word := func(r rune) bool { return digit(r) || 'A' <= r && r <= 'Z' || r == '_' || 'a' <= r && r <= 'z' }
	space := func(r rune) bool { return r == '\t' || r == '\n' || r == '\f' || r == '\r' || r == ' ' }
	for _, name := range []string{"L", "Letter", "Pd", "Sk", "Ps", "Pe", "Po", "Cc", "Zs", "C", "Cn"} {
		table := categoryTable(name)
		in := func(r rune) bool { return unicode.Is(table, r) }
		var probes []rune
		for _, r := range table.R16 {
			probes = append(probes, rune(r.Lo)-1, rune(r.Lo), rune(r.Hi), rune(r.Hi)+1)
		}
		for _, r := range table.R32 {
			probes = append(probes, rune(r.Lo)-1, rune(r.Lo), rune(r.Hi), rune(r.Hi)+1)
		}
		for r := rune(0); r <= unicode.MaxRune; r += 97 {
			probes = append(probes, r)
		}
		lu := ucd.Category("Lu")
		for form, want := range map[string]func(rune) bool{
			`^\p{%s}$`:           in,
			`^\P{%s}$`:           func(r rune) bool { return !in(r) },
			`^[\p{%s}\d]$`:       func(r rune) bool { return in(r) || digit(r) },
			`^[^\p{%s}\d]$`:      func(r rune) bool { return !in(r) && !digit(r) },
			`^[\P{%s}\d]$`:       func(r rune) bool { return !in(r) || digit(r) },
			`^[^\P{%s}\d]$`:      func(r rune) bool { return in(r) && !digit(r) },
			`^[a\p{%s}\p{Lu}-]$`: func(r rune) bool { return r == 'a' || r == '-' || in(r) || unicode.Is(lu, r) },
			`^[\p{%s}\S]$`:       func(r rune) bool { return in(r) || !space(r) },
			`^[^\p{%s}\W]$`:      func(r rune) bool { return !in(r) && word(r) },
			`^[\P{%s}\s!-/]$`:    func(r rune) bool { return !in(r) || space(r) || '!' <= r && r <= '/' },
		} {
			expr := fmt.Sprintf(form, name)
			re, err := compileRegexpWithin(expr, nil)
			if err != nil {
				t.Fatalf("%s: %v", expr, err)
			}
			for _, r := range probes {
				if r < 0 || r > unicode.MaxRune || 0xD800 <= r && r <= 0xDFFF {
					continue
				}
				if got := re.MatchString(string(r)); got != want(r) {
					t.Errorf("%s matches U+%04X: %v, want %v", expr, r, got, !got)
					break
				}
			}
		}
	}
}

// The ranges counted toward maxPatternSize are those of the pinned table,
// joined where they touch, whatever the toolchain: \p{C} counts 712, so
// eleven are admitted and twelve refused.
func TestPrescan_CountsTheRangesOfThePinnedTables(t *testing.T) {
	if n := unicodeClassRanges("C"); n != 712 {
		t.Errorf(`\p{C} counts %d ranges, want 712`, n)
	}
	if _, _, err := prescan(strings.Repeat(`\p{C}`, 11)); err != nil {
		t.Errorf(`eleven \p{C} refused: %v`, err)
	}
	if _, _, err := prescan(strings.Repeat(`\p{C}`, 12)); err == nil || !strings.HasPrefix(err.Error(), "regexp: its Unicode classes hold more than ") {
		t.Errorf(`twelve \p{C}: %v, want refused with the bound's text, the text verification/vectors matches`, err)
	}
}

// A class that holds a Unicode class is written out as the code points it
// holds, its other members included, so Go reads no more ranges for it than
// its program counts: [\p{L}\D] is \D's two ranges, not L's and \D.
func TestPrescan_WritesAClassAsTheCodePointsItHolds(t *testing.T) {
	for _, expr := range []string{
		`[\p{L}\D]`, `[^\p{L}\D]`, `[\p{Lu}\W]`, `[\P{L}\w]`, `[\p{Nd}\S]`, `[\p{L}\p{Lu}a-z]`,
		`[\p{C}\P{C}]`, `[^\p{C}\P{C}]`, `[\p{Lu}!-~]`, `[\P{Cn}\x00-\x7f]`,
	} {
		goExpr, _, err := prescan(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		re, err := syntax.Parse(goExpr, syntax.Perl)
		if err != nil {
			t.Fatalf("%s written out as %.80q: %v", expr, goExpr, err)
		}
		ranges := len(re.Rune) / 2
		if re.Op != syntax.OpCharClass {
			ranges = 1
		}
		if bound := 24*(ranges+1) + 4; len(goExpr) > bound {
			t.Errorf("%s written out in %d bytes for a class of %d ranges, want at most %d", expr, len(goExpr), ranges, bound)
		}
	}
}

// A control character is written as an escape, C1 controls included.
func TestAppendRanges_EscapesControls(t *testing.T) {
	got := string(appendRanges(nil, [][2]rune{{0x00, 0x1F}, {0x7F, 0x9F}, {0xA0, 0xA0}}))
	if want := `\x{0}-\x{1f}\x{7f}-\x{9f}` + " "; got != want {
		t.Errorf("appendRanges = %q, want %q", got, want)
	}
}

// unicodeClassRanges is the ranges prescan counts for the general category
// name (one more for a negated one), else 0.
func unicodeClassRanges(name string) int { return len(categoryRanges(name)) }

// classPieces are what the draws below build expressions from: Unicode
// classes, by short and long name, and what they share a class with.
var classPieces = []string{
	`\p{L}`, `\P{L}`, `\p{Letter}`, `\p{Lu}`, `\P{Nd}`, `\p{digit}`, `\p{C}`, `\P{C}`, `\p{Cn}`, `\p{Cs}`, `\p{Pd}`, `\p{Sk}`, `\p{Ps}`, `\p{Pe}`, `\p{Po}`, `\P{Zs}`,
	`\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `a`, `z`, `-`, `\-`, `\]`, `\[`, `\\`, `\^`, `^`, `a-z`, `!-/`, `\x00-\x1f`, `\x7f`, `é`, "\u0085", "\u2028", "\uFFFD", "\uFFFF", "\U0010FFFF", `.`, `$`,
}

// drawClass is a class of one to six pieces, negated or not.
func drawClass(rng *rand.Rand) string {
	var b strings.Builder
	b.WriteByte('[')
	if rng.IntN(2) == 0 {
		b.WriteByte('^')
	}
	for range 1 + rng.IntN(6) {
		b.WriteString(classPieces[rng.IntN(len(classPieces))])
	}
	b.WriteByte(']')
	return b.String()
}

// Go's parser never reads a category's name: what prescan writes out names
// none, on any toolchain.
func TestPrescan_WritesNoCategoryNameForGo(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 20000 {
		expr := drawClass(rng) + classPieces[rng.IntN(16)] + `+`
		goExpr, _, err := prescan(expr)
		if err != nil {
			continue
		}
		if strings.Contains(goExpr, `\p`) || strings.Contains(goExpr, `\P`) {
			t.Fatalf("%q written out as %.80q, which names a category", expr, goExpr)
		}
	}
}

// Where the toolchain's tables are Unicode 15.0.0, Go reads what prescan
// writes out as it reads the expression itself: the same parse, for classes
// that mix Unicode classes with every other member, negated or not, and for
// Unicode classes outside a class.
func TestPrescan_WritesWhatGoReadsWithUnicode15(t *testing.T) {
	if unicode.Version != "15.0.0" {
		t.Skipf("Go's unicode tables are %s; this compares with Unicode 15.0.0's", unicode.Version)
	}
	rng := rand.New(rand.NewPCG(5, 6))
	compared := 0
	for range 20000 {
		expr := drawClass(rng) + classPieces[rng.IntN(16)]
		goExpr, _, err := prescan(expr)
		if err != nil {
			continue
		}
		want, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatalf("%q: Go does not read it: %v", expr, err)
		}
		got, err := syntax.Parse(goExpr, syntax.Perl)
		if err != nil {
			t.Fatalf("%q written out as %.80q: %v", expr, goExpr, err)
		}
		if !got.Equal(want) {
			t.Fatalf("%q: Go reads it as %.200s, but what prescan writes out as %.200s", expr, want, got)
		}
		compared++
	}
	if compared < 15000 {
		t.Fatalf("only %d of the draws were accepted: the draw tests little", compared)
	}
}

// An expression costs the ranges of the Unicode tables prescan read for it
// when they are more than its program: a class whose Unicode classes cancel
// writes out one range, but what it takes from a total is what it read. Its
// Size, by which the library charges matching it, is its program's.
func TestCompileRegexp_ChargesTheTableRangesRead(t *testing.T) {
	expr := `[` + strings.Repeat(`\p{C}\P{C}`, 5) + `]`
	read := 5 * (2*unicodeClassRanges("C") + 1)
	left := int64(2 * maxPatternSize)
	re, err := compileRegexpWithin(expr, &left)
	if err != nil {
		t.Fatal(err)
	}
	if taken := 2*maxPatternSize - left; taken < int64(read) {
		t.Errorf("took %d from the total, want at least the %d table ranges read", taken, read)
	}
	if size := re.(sizedRegexp).Size(); size > 10 {
		t.Errorf("Size %d, want its program's, a class of one range", size)
	}
}

// A pattern whose Unicode classes read as many ranges as prescan admits still
// compiles, alone, within the total of the smallest schema.
func TestCompileRegexp_AdmitsAPatternThatReadsTheMostRanges(t *testing.T) {
	c := unicodeClassRanges("C")
	expr := `[` + strings.Repeat(`\p{C}`, maxPatternSize/c) + strings.Repeat(`\p{Zl}`, maxPatternSize%c) + `]`
	if unicodeClassRanges("Zl") != 1 {
		t.Fatalf("Zl counts %d ranges", unicodeClassRanges("Zl"))
	}
	total := newPatternTotal(0)
	before := total.left
	if _, err := total.compile(expr); err != nil {
		t.Fatalf("a pattern that reads %d ranges refused: %v", maxPatternSize, err)
	}
	if taken := before - total.left; taken < maxPatternSize {
		t.Errorf("took %d from the total, want at least %d", taken, maxPatternSize)
	}
}

// An expression prescan accepts costs the table ranges it read even when it
// is then refused, its program too large or Go refusing it: what is left of
// a total goes down by them.
func TestCompileRegexp_ChargesARefusedExpressionTheRangesRead(t *testing.T) {
	read := 11 * unicodeClassRanges("C")
	for _, expr := range []string{
		strings.Repeat(`\p{C}`, 11) + `.{200}`,
		strings.Repeat(`\p{C}`, 11) + `(?:(?:a{1000}){1000})`,
	} {
		left := int64(2 * maxPatternSize)
		_, err := compileRegexpWithin(expr, &left)
		if err == nil {
			t.Fatalf("%.40q admitted", expr)
		}
		if strings.HasSuffix(expr, ".{200}") && !strings.HasPrefix(err.Error(), "regexp: its program has more than ") {
			t.Errorf("%.40q: %v, want refused with the bound's text, the text verification/vectors matches", expr, err)
		}
		if taken := 2*maxPatternSize - left; taken < int64(read) {
			t.Errorf("%.40q took %d from the total, want at least the %d ranges read", expr, taken, read)
		}
	}
}

// A value checked as format "regex" after the schema compiled costs the table
// ranges read for it, and so does its refusal once prescan accepted it: the
// refusal says the cost (Size), for the library to charge.
func TestCompileValue_CostsTheRangesReadRefusedOrNot(t *testing.T) {
	read := 11 * unicodeClassRanges("C")
	re, err := compileValue(`[` + strings.Repeat(`\p{C}`, 11) + `]`)
	if err != nil {
		t.Fatal(err)
	}
	if size := re.(sizedRegexp).Size(); size < read {
		t.Errorf("Size %d, want at least the %d ranges read", size, read)
	}
	_, err = compileValue(strings.Repeat(`\p{C}`, 11) + `.{200}`)
	var sized interface{ Size() int }
	if !errors.As(err, &sized) || sized.Size() < read {
		t.Errorf("refusal %v, want one that says a cost of at least %d", err, read)
	}
	if _, err := compileValue(`(?i)a`); errors.As(err, &sized) {
		t.Errorf("a refusal of prescan's says a cost %d; the library charges its bytes", sized.Size())
	}
}

// categoryTable is the pinned table of the general category name names, by
// its short name or a long one, else nil.
func categoryTable(name string) *unicode.RangeTable { return ucd.Category(shortName(name)) }

// An expression whose program costs more than what is left, once its ranges
// read were taken, is refused, and what was taken stays taken.
func TestCompileRegexp_ARefusalPastTheTotalKeepsWhatWasTaken(t *testing.T) {
	read := unicodeClassRanges("Lu")
	left := int64(read + onePassGuardSize + 10)
	if _, err := compileRegexpWithin(`\p{Lu}.{1000}`, &left); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("%v, want the total refused", err)
	}
	if left != 10 {
		t.Errorf("%d left, want 10: the %d ranges read and the guard taken", left, read)
	}
}
