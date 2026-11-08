package schemadoc

import (
	"math/rand/v2"
	"regexp/syntax"
	"runtime"
	"strings"
	"testing"
	"time"
)

// patternSize is at least the instructions Go's regexp compiles, for every
// shape of expression: nullable repeats, empty repeats, captures,
// alternations, classes and the program's own instructions.
func TestPatternSize_IsAtLeastTheProgram(t *testing.T) {
	for _, expr := range []string{
		``, `a`, `abc`, `[a-c]`, `\pL`, `.`, `^$`, `\b\B`, `(?:)`,
		`(a)`, `(a(b(c)))`, `(?:a|b|c)`, `a|b|cd|`,
		`a*`, `a+`, `a?`, `a*?`, `(?:^)*`, `(?:a?)*`, `(?:a*)*`, `(?:a*)+`, `(?:a?)?`,
		`a{3}`, `a{0}`, `a{0,0}`, `a{0,3}`, `a{2,}`, `a{1000}`,
		`(?:a?){0,1000}`, `(?:(?:^)*){0,1000}`, `(?:a|b){5,10}`, `(?:[a-c]x?){0,1000}`,
		`(?:(?:a*){3}){10}`, `(?:\pL?){100}`, `(?i)k`, `(?i)[a-z]{20}`,
	} {
		re, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
		if size := patternSize(re); size < int64(len(prog.Inst)) {
			t.Errorf("%q: size %d, but the program has %d instructions", expr, size, len(prog.Inst))
		}
	}
}

// The scan accepts only the forms whose meaning ECMA-262 (11th edition, which
// JSON Schema 2020-12 uses) and Go's regexp share, and refuses every other
// form before Go parses it.
func TestPrescan_AcceptsOnlyTheSharedGrammar(t *testing.T) {
	accepted := []string{
		``, `a`, `abc`, `.`, `^a$`, `a|b|`, `(a)`, `(?:a)`, `(?<name>a)`, `(?<_n1>a)`,
		`a*`, `a+`, `a?`, `a*?`, `a+?`, `a??`, `a{3}`, `a{2,}`, `a{2,5}`, `a{2,5}?`, `a{0}`, `a{10}`, `a{0,10}`, `a{10,}`, `(ab)*`, `[a-z]+`,
		`\d\D\w\W\s\S`, `\bfoo\B`, `\t\n\v\f\r`, `\x41`, `\p{L}`, `\P{Lu}`, `\p{Nd}+`,
		`\^\$\\\.\*\+\?\(\)\[\]\{\}\|\/`,
		`[abc]`, `[^abc]`, `[a-z0-9_]`, `[a-a]`, `[\x41-\x41]`, `[!->]`, `[\t-\r]`, `[-a]`, `[a-]`, `[\d\w\s]`, `[\]\[\-\\]`, `[\x41-\x5A]`, `[\p{L}\p{Nd}_-]`, `[(?i)]`, `[.*+?|^$]`,
		`é+`, `[à-ÿ]`, `^\S+@\S+$`, `^[a-zA-Z\d][a-zA-Z\d._+()-]{0,254}$`,
	}
	refused := []string{
		`(?i)a`, `(?i:a)`, `(?s).`, `(?-i)a`, `(?U)a*`, `(?P<n>a)`, `(?=a)`, `(?!a)`, `(?<=a)`, `(?<!a)`, `(?<1a>a)`,
		`\Qa\E`, `\Q[\E(?i)a`, `\pL`, `\p{l}`, `\p{Greek}`, `\p{^L}`, `\p{Script=Greek}`, `\p{L`, `\p`,
		`\uFFFF`, `\x{41}`, `\x4`, `\0`, `\1`, `\k<n>`, `\cA`, `\a`, `\e`, `\z`, `\A`, `\C`,
		`[b-a]`, `[\x42-\x41]`, `[>-!]`, `[\.-\(]`,
		`[]`, `[^]`, `[]a]`, `[[:alpha:]]`, `[a[b]`, `[\b]`, `[\d-z]`, `[a-\w]`, `[a`, `a]`, `a}`, `a{`, `a{,3}`, `a{x}`, `{3}`, `a{01}`, `a{00}`, `a{1,02}`, `a{0,01}`,
		`*a`, `a**`, `a+*`, `(*a)`, `|*`, `^*`, `$+`, `\b?`, `(a`, `a)`, `(?:a`, `a\`,
		"[" + strings.Repeat("[:a", 100) + "]", "[\xbf]", "a\xff",
	}
	for _, expr := range accepted {
		if err := prescan(expr); err != nil {
			t.Errorf("%q refused: %v", expr, err)
		}
	}
	for _, expr := range refused {
		if err := prescan(expr); err == nil {
			t.Errorf("%.40q accepted", expr)
		}
	}
}

// Every expression the scan accepts, Go parses and compiles: the scan does
// not let through a form Go reads otherwise or cannot read.
func TestPrescan_WhatItAcceptsGoReads(t *testing.T) {
	for _, expr := range []string{
		`^[a-zA-Z\d][a-zA-Z\d._+()-]{0,254}$`, `(?<name>a)\k`, `[\p{L}\p{Nd}_-]+`, `\x41[\x41-\x5A]`, `a{2,5}?`, `[-a]|[a-]`,
	} {
		if prescan(expr) != nil {
			continue
		}
		if _, err := syntax.Parse(expr, syntax.Perl); err != nil {
			t.Errorf("%q: the scan accepts it, Go does not: %v", expr, err)
		}
	}
}

// The Unicode classes an expression names are counted by the ranges Go's
// parser copies from their tables, and an expression whose classes hold more
// than maxPatternSize ranges is refused.
func TestPrescan_BoundsUnicodeClasses(t *testing.T) {
	letters := unicodeClassRanges("L")
	if letters < 100 {
		t.Fatalf("\\p{L} counts %d ranges", letters)
	}
	within := strings.Repeat(`\p{L}`, maxPatternSize/letters)
	past := within + `\p{L}`
	for expr, refused := range map[string]bool{
		within: false, past: true, `[` + past + `]`: true, strings.Repeat(`\P{L}`, maxPatternSize/letters+1): true,
	} {
		if err := prescan(expr); (err != nil) != refused {
			t.Errorf("%.40q: %v, want refused %v", expr, err, refused)
		}
	}
}

// The scan reads an expression once: its time is linear in the expression's
// length, whatever the forms it holds. Each expression repeats a form the
// scan accepts and ends in one it refuses, so the scan reads all of it.
// (Sixteen times as long takes about sixteen times as long; a scan that
// searched the rest of the expression at each step would take about 256
// times.)
func TestPrescan_IsLinear(t *testing.T) {
	timeOf := func(s string) time.Duration {
		best := time.Hour
		for range 5 {
			start := time.Now()
			for range 20 {
				prescan(s)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	for _, unit := range []string{"a", "[a-z]", "(?:a)", "(a)", "a{2,5}", `\x41`, `[\x41-\x5A]`, `\d\w`, "a|", "[^a]", `\.`, "[-a]"} {
		if err := prescan(strings.Repeat(unit, 2000)); err != nil {
			t.Fatalf("%q: %v", unit, err)
		}
		short := timeOf(strings.Repeat(unit, 2000) + "(?i)")
		long := timeOf(strings.Repeat(unit, 32000) + "(?i)")
		if ratio := float64(long) / float64(max(short, time.Microsecond)); ratio > 64 {
			t.Errorf("%q: 16 times as long took %.0f times as long", unit, ratio)
		}
	}
}

// parsesWithinItsSize checks what compileRegexpWithin relies on for an
// expression the scan accepts: Go parses it, and the program it compiles,
// guard included, has at most patternSize + onePassGuardSize instructions.
func parsesWithinItsSize(t *testing.T, expr string) {
	t.Helper()
	if prescan(expr) != nil {
		return
	}
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		t.Errorf("%q: the scan accepts it, Go does not parse it: %v", expr, err)
		return
	}
	guarded, err := syntax.Parse(onePassGuard+"(?:"+expr+")", syntax.Perl)
	if err != nil {
		t.Errorf("%q: Go does not parse it guarded: %v", expr, err)
		return
	}
	prog, err := syntax.Compile(guarded.Simplify())
	if err != nil {
		t.Errorf("%q: Go does not compile it: %v", expr, err)
		return
	}
	if size := patternSize(parsed) + onePassGuardSize; int64(len(prog.Inst)) > size {
		t.Errorf("%q: %d instructions, more than its size %d", expr, len(prog.Inst), size)
	}
}

// Expressions drawn at random from the pieces of the grammar and near it:
// every one the scan accepts, Go parses, within its size.
func TestPrescan_WhatItAcceptsGoParsesWithinItsSize(t *testing.T) {
	pieces := []string{
		"a", "b", "é", ".", "^", "$", "|", "(", ")", "(?:", "(?<n", ">", "[", "]", "[^", "-", "\\", "\\d", "\\w", "\\s",
		"\\b", "\\B", "\\x41", "\\x4", "\\p{L}", "\\P{Nd}", "\\p{", "{", "}", ",", "0", "1", "2", "*", "+", "?", ":", "=", "!",
		"\\t", "\\.", "\\[", "\\]", "\\-", "\\/", "\\{", "(?i)",
	}
	rng := rand.New(rand.NewPCG(1, 2))
	accepted := 0
	for range 200000 {
		var b strings.Builder
		for range 1 + rng.IntN(10) {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		expr := b.String()
		if prescan(expr) == nil {
			accepted++
		}
		parsesWithinItsSize(t, expr)
	}
	if accepted < 10000 {
		t.Fatalf("only %d of the expressions drawn were accepted: the draw tests little", accepted)
	}
}

func FuzzPrescan(f *testing.F) {
	for _, expr := range []string{
		`^[a-zA-Z\d][a-zA-Z\d._+()-]{0,254}$`, `[\p{L}\p{Nd}_-]+`, `\x41[\x41-\x5A]`, `a{2,5}?`, `[-a]|[a-]`, `(?<name>a)(?:b|c)*`,
	} {
		f.Add(expr)
	}
	f.Fuzz(parsesWithinItsSize)
}

// One Compile's regular expressions take, together, at most what its total
// allows: each takes its size from what is left, and one past it is refused.
// Once Compile has returned, the engine takes nothing from the total.
func TestPatternTotal_BoundsTheSizesTogether(t *testing.T) {
	size := func(expr string) int64 {
		re, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		return patternSize(re) + onePassGuardSize
	}
	expr := `a{40}`
	total := &patternTotal{left: 2*size(expr) + 1}
	for i := range 2 {
		if _, err := total.compile(expr); err != nil {
			t.Fatalf("compile %d: %v", i, err)
		}
	}
	if _, err := total.compile(expr); err == nil {
		t.Error("a third compile within a total of two was not refused")
	}
	total.compiled = true
	if _, err := total.compile(expr); err != nil || total.left != 1 {
		t.Errorf("after Compile: %v, %d left", err, total.left)
	}
}

// A pattern is compiled so that Go does not analyse it as one-pass: that
// analysis, for an anchored program under 1,000 instructions, copies each
// class's ranges through each capture and empty-width instruction, taking
// memory in their product where the size counts their sum. Many empty groups
// before a large class, anchored, allocate a few hundred kilobytes, not tens
// of megabytes.
func TestCompileRegexpWithin_AvoidsTheOnePassAnalysis(t *testing.T) {
	var class strings.Builder
	class.WriteByte('[')
	for i := range 6000 {
		class.WriteRune(rune(0x100 + 2*i))
	}
	class.WriteByte(']')
	expr := "^" + strings.Repeat("()", 300) + class.String() + "$"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	re, err := compileRegexpWithin(expr, nil)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Errorf("compiling allocated %d MB", alloc>>20)
	}
	if !re.MatchString(string(rune(0x100))) || re.MatchString("a") || re.String() != expr {
		t.Errorf("the compiled pattern matches otherwise, or says %.40q", re.String())
	}
}

// Groups nest at most maxGroupDepth deep. Go's parser copies what a group
// holds into each group around it, so its work grows with an expression's
// length times how deep its groups nest; SchemaStore's patterns nest at most
// 7 deep.
func TestPrescan_BoundsTheNestingOfGroups(t *testing.T) {
	nest := func(open string, depth int) string {
		return strings.Repeat(open, depth) + "a" + strings.Repeat(")", depth)
	}
	for _, open := range []string{"(", "(?:"} {
		if err := prescan(nest(open, maxGroupDepth)); err != nil {
			t.Errorf("%q %d deep: %v", open, maxGroupDepth, err)
		}
		if err := prescan(nest(open, maxGroupDepth+1)); err == nil {
			t.Errorf("%q %d deep accepted", open, maxGroupDepth+1)
		}
		if err := prescan(strings.Repeat(nest(open, maxGroupDepth), 100)); err != nil {
			t.Errorf("100 groups of %q %d deep, one after another: %v", open, maxGroupDepth, err)
		}
	}
}

// Parsing and compiling an expression, refused or not, allocates memory
// linear in its length, however its groups nest and however small the
// program it compiles to: groups nested deep, and a body repeated {0} times,
// which compiles to almost nothing but is parsed twice.
func TestCompileRegexpWithin_AllocatesLinearlyInTheLength(t *testing.T) {
	deep := func(depth int) string { return strings.Repeat("(?:a*", depth) + strings.Repeat(")", depth) }
	for name, expr := range map[string]string{
		"4,000 groups nested, repeated {0} times":       deep(4000) + "{0}",
		"groups 31 deep, inside one repeated {0} times": "(?:" + strings.Repeat(deep(31), 250) + "){0}",
		"groups 32 deep, then a pattern past the size":  strings.Repeat(deep(32), 250),
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := compileRegexpWithin(expr, nil)
		runtime.ReadMemStats(&after)
		if perByte := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(expr)); perByte > 400 {
			t.Errorf("%s (%d bytes, err %v): %.0f bytes allocated per byte", name, len(expr), err, perByte)
		}
	}
}
