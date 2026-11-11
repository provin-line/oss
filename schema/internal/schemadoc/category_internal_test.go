package schemadoc

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"
)

// The scan takes each long name and alias of a general category as ECMA-262
// spells it, and Go's parser reads it as the category its short name names:
// the same parse, alone, negated and in classes, counted as the same ranges.
func TestPrescan_AcceptsCategoryAliases(t *testing.T) {
	if len(categoryAliases) != 42 {
		t.Fatalf("%d aliases, ES2020's table has 42", len(categoryAliases))
	}
	for name, short := range categoryAliases {
		if unicode.Categories[short] == nil {
			t.Fatalf("%s names %s, which Go has no table for", name, short)
		}
		if got := unicode.CategoryAliases[name]; got != short {
			t.Errorf("Go reads %s as %q, ES2020 as %s", name, got, short)
		}
		for _, form := range []string{`\p{%s}`, `\P{%s}`, `[^\p{%s}]`, `[\P{%s}a-z]`} {
			expr := fmt.Sprintf(form, name)
			if err := prescan(expr); err != nil {
				t.Errorf("%s refused: %v", expr, err)
			}
			long, err := syntax.Parse(expr, syntax.Perl)
			if err != nil {
				t.Fatalf("Go does not read %s: %v", expr, err)
			}
			brief, err := syntax.Parse(fmt.Sprintf(form, short), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			if long.String() != brief.String() {
				t.Errorf("Go reads %s otherwise than %s", expr, fmt.Sprintf(form, short))
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
		if err := prescan(`\p{` + name + `}`); err == nil {
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
		if err := prescan(expr); err == nil {
			t.Errorf("%s accepted", expr)
		}
	}
}

// A long name counts against the bound on Unicode classes as its short name
// does: the same number of repeats is refused.
func TestPrescan_BoundsCategoryAliasesAsTheirShortNames(t *testing.T) {
	n := maxPatternSize/unicodeClassRanges("L") + 1
	for _, name := range []string{"L", "Letter"} {
		if err := prescan(strings.Repeat(`\p{`+name+`}`, n-1)); err != nil {
			t.Errorf("%d of %s refused: %v", n-1, name, err)
		}
		if err := prescan(strings.Repeat(`\p{`+name+`}`, n)); err == nil {
			t.Errorf("%d of %s accepted", n, name)
		}
	}
}
