package schemadoc

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/jsonschema"
	"github.com/provin-line/oss/internal/ucd"
)

// maxPatternSize bounds every regular expression the library compiles here
// (a schema's pattern and patternProperties names, and a payload value
// checked as format "regex") by the size of its program: patternSize, the
// instructions once its repeats are expanded, each character class counted
// with its ranges. Go's regexp compiles a program in time and memory linear
// in that size (at most about 150 ns and 150 bytes per instruction,
// measured, without the one-pass analysis: onePassGuard), and matches a
// position against it in time at most linear in it. The 1,027 schemas of
// SchemaStore hold no pattern above 5,415.
const maxPatternSize = 8192

// maxGroupDepth bounds how deep an expression's groups nest, capturing or
// not. Go's parser copies what a non-capturing group holds into the
// concatenation around it, at each level, and sorts a class again at each
// group around it, so parsing takes time and memory in the expression's
// length times that depth: at 8, at most about 80 ns and 95 bytes per byte,
// and at 32, about 120 ns and 110 bytes per byte (measured), two to three
// times an expression without groups. The 8,237 patterns of SchemaStore nest
// at most 7 deep (one of them; the others at most 4). It is
// defaultMaxGroupDepth unless maxGroupDepthEnv sets it, read once, as the
// package is initialized (parseMaxGroupDepth); a setting it does not accept
// panics there, so no program that imports the package starts with one.
var maxGroupDepth = mustMaxGroupDepth()

const (
	// defaultMaxGroupDepth is maxGroupDepth when maxGroupDepthEnv is unset
	// or empty.
	defaultMaxGroupDepth = 8
	// maxGroupDepthCeiling is the most maxGroupDepthEnv may set
	// maxGroupDepth to: the depth at which the steps charged for parsing an
	// expression are measured (jsonschema.PatternParseStepsPerByte).
	maxGroupDepthCeiling = 32
	// maxGroupDepthEnv is the environment variable that sets maxGroupDepth.
	maxGroupDepthEnv = "PROVIN_SCHEMA_REGEXP_MAX_GROUP_DEPTH"
)

// mustMaxGroupDepth returns the bound maxGroupDepthEnv sets, panicking on a
// setting parseMaxGroupDepth does not accept.
func mustMaxGroupDepth() int {
	v, set := os.LookupEnv(maxGroupDepthEnv)
	d, err := parseMaxGroupDepth(v, set)
	if err != nil {
		panic(err)
	}
	return d
}

// parseMaxGroupDepth reads maxGroupDepthEnv's value v: unset or empty is
// defaultMaxGroupDepth, and anything else must be a decimal integer from 1
// to maxGroupDepthCeiling.
func parseMaxGroupDepth(v string, set bool) (int, error) {
	if !set || v == "" {
		return defaultMaxGroupDepth, nil
	}
	d, err := strconv.Atoi(v)
	if err != nil || strings.TrimLeft(v, "0123456789") != "" || d < 1 || d > maxGroupDepthCeiling {
		return 0, fmt.Errorf("schema: %s=%q: want a decimal integer from 1 to %d, or unset or empty for %d", maxGroupDepthEnv, v, maxGroupDepthCeiling, defaultMaxGroupDepth)
	}
	return d, nil
}

// compileRegexpWithin compiles expr with Go's regexp, as prescan writes it
// for Go, refusing, before it parses it, what would make parsing it take more
// than about 150 ns per byte with groups nested at most 8 deep and 240 ns at
// 32 (maxGroupDepth), or per range of its Unicode classes for each
// group around them (Go's parser sorts a class again at each), or memory more
// than linear in its length and maxPatternSize (prescan), and before it
// compiles it, a program larger than maxPatternSize. When left is not nil, it
// takes expr's cost from that total (compileCosting), refusing an expression
// that costs more than is left. It says the size of the program it compiles
// (sizedRegexp), by which the library charges matching it.
func compileRegexpWithin(expr string, left *int64) (jsonschema.Regexp, error) {
	re, size, _, err := compileCosting(expr, left)
	if err != nil {
		return nil, err
	}
	return sizedRegexp{re, expr, int(size)}, nil
}

// compileValue compiles a payload's value checked as format "regex", which
// the library charges by what compiling it costs and never matches: its Size
// is the cost (compileCosting), and so is the Size of its refusal once
// prescan has accepted it (costedRefusal), which the library charges too.
func compileValue(expr string) (jsonschema.Regexp, error) {
	re, _, cost, err := compileCosting(expr, nil)
	if err != nil {
		if cost > 0 {
			return nil, costedRefusal{err, int(cost)}
		}
		return nil, err
	}
	return sizedRegexp{re, expr, int(cost)}, nil
}

// compileCosting compiles expr as compileRegexpWithin says, and returns the
// program, its size, and what compiling expr costs: the size of its program
// or, where they are more, the ranges of the Unicode tables prescan read for
// it (a class whose Unicode classes cancel reads more than it writes out). On
// a refusal, the cost is what was taken by then: nothing when prescan refused
// expr, the ranges read and the guard once it accepted expr, and the
// program's size once Go parsed expr within the bounds. With a total (left),
// it takes the ranges read and the guard as soon as prescan has read them,
// before Go parses expr, so an expression refused after that has paid for
// them, and the rest of the cost once Go has parsed it.
func compileCosting(expr string, left *int64) (*regexp.Regexp, int64, int64, error) {
	room := maxPatternSize
	if left != nil {
		room = int(min(int64(maxPatternSize), max(*left-onePassGuardSize, 0)))
	}
	goExpr, read, err := prescanWithin(expr, room)
	if err != nil {
		return nil, 0, 0, err
	}
	cost := int64(read) + onePassGuardSize
	if left != nil {
		if cost > *left {
			return nil, 0, 0, errPastTotal
		}
		*left -= cost
	}
	parsed, err := syntax.Parse(goExpr, syntax.Perl)
	if err != nil {
		return nil, 0, cost, err
	}
	size := patternSize(parsed) + onePassGuardSize
	if size > maxPatternSize {
		return nil, 0, cost, fmt.Errorf("regexp: its program has more than %d instructions", maxPatternSize)
	}
	if more := size - cost; more > 0 {
		if left != nil {
			if more > *left {
				return nil, 0, cost, errPastTotal
			}
			*left -= more
		}
		cost = size
	}
	re, err := regexp.Compile(onePassGuard + "(?:" + goExpr + ")")
	if err != nil {
		return nil, 0, cost, err
	}
	return re, size, cost, nil
}

// costedRefusal is compileValue's refusal of a value prescan accepted: the
// error, and what compiling the value cost by then (Size), which the library
// charges.
type costedRefusal struct {
	err  error
	size int
}

func (e costedRefusal) Error() string { return e.err.Error() }
func (e costedRefusal) Unwrap() error { return e.err }

// Size is what compiling the value cost before it was refused.
func (e costedRefusal) Size() int { return e.size }

// onePassGuard begins every program compiled here with a capture, so Go does
// not analyse it as one-pass (regexp.compileOnePass takes only a program
// whose first instruction is the beginning of the text). That analysis, for
// an anchored program under 1,000 instructions, copies each class's ranges
// through each capture and empty-width instruction, taking time and memory
// in their product where patternSize counts their sum (65 MB for 300 empty
// groups before a class of 6,000 ranges; 0.4 MB with the guard). A pattern
// matches the same with it: the capture is empty, and the group keeps the
// expression's alternation inside. onePassGuardSize is the instructions it
// adds.
const (
	onePassGuard     = "()"
	onePassGuardSize = 3
)

// patternTotalBase and patternTotalBytesPerInstruction bound the regular
// expressions one Compile compiles, by their costs summed
// (compileRegexpWithin: the size of each program or the ranges of the Unicode
// tables read for it, each expression counted each time it is compiled: a
// pattern is compiled again where the metaschema checks it as format "regex",
// as the metaschemas of every draft are compiled asserting formats). A schema
// of b bytes may compile patternTotalBase + b/4 instructions: one pattern of
// about maxPatternSize twice, and one instruction per 4 bytes past that. Go's
// regexp allocates about 150 bytes per instruction it compiles, so compiling
// them allocates at most about (2^14 + b/4) × 150 bytes: about 40 MB for a
// schema of 1 MiB.
//
// The values are measured. Of the 1,027 schemas of SchemaStore, the 882 that
// compile here use at most 1.78 instructions per byte (a schema of 1 KB),
// 0.33 at the 99th percentile, and 24,774 in all at most (a schema of 7.6
// MB); none needs more than this bound.
const (
	patternTotalBase                = 2 * maxPatternSize
	patternTotalBytesPerInstruction = 4
)

// patternTotal is the size left to the regular expressions one Compile
// compiles. Once Compile has returned, the engine compiles values checked as
// format "regex", which the validation's budget charges, and the total is
// not used.
type patternTotal struct {
	left     int64
	compiled bool
}

func newPatternTotal(documentBytes int) *patternTotal {
	return &patternTotal{left: patternTotalBase + int64(documentBytes)/patternTotalBytesPerInstruction}
}

// compile is the library's RegexpEngine for one Compile.
func (t *patternTotal) compile(expr string) (jsonschema.Regexp, error) {
	if t.compiled {
		return compileValue(expr)
	}
	return compileRegexpWithin(expr, &t.left)
}

// sizedRegexp is a compiled regular expression, the expression it was
// compiled from, and the size it says: its program's, for an expression the
// library matches (compileRegexpWithin), or what compiling it cost, for a
// payload's value checked as format "regex" (compileValue).
type sizedRegexp struct {
	*regexp.Regexp
	expr string
	size int
}

// String is the expression as the schema or the payload wrote it.
func (r sizedRegexp) String() string { return r.expr }

// Size is the size the library charges: per byte matched for an expression
// it matches (jsonschema.PatternInstructionsPerStep), and once for a value
// it compiles as format "regex".
func (r sizedRegexp) Size() int { return r.size }

// patternSize is an upper bound of the instructions of re's program: the
// program's own two (fail and match), and for each node one per rune of a
// literal, one per class and one per range in it, two per capture, two per
// star, plus or quest besides its body (a star of a body that can match
// empty compiles to two), and a repeat's body and two more as many times as
// its maximum (once more than its minimum when it has none), at least one. It
// saturates past maxPatternSize, so it does not overflow. Its work is linear
// in the size of the parsed tree.
func patternSize(re *syntax.Regexp) int64 {
	return min(2+nodeSize(re), maxPatternSize+1)
}

func nodeSize(re *syntax.Regexp) int64 {
	const ceiling = maxPatternSize + 1
	sat := func(x int64) int64 { return min(x, ceiling) }
	switch re.Op {
	case syntax.OpLiteral:
		return sat(int64(len(re.Rune)))
	case syntax.OpCharClass:
		return sat(1 + int64(len(re.Rune)/2))
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return sat(2 + nodeSize(re.Sub[0]))
	case syntax.OpRepeat:
		n := int64(re.Max)
		if re.Max < 0 {
			n = int64(re.Min) + 1
		}
		return sat(max(n*(2+nodeSize(re.Sub[0])), 1))
	case syntax.OpConcat, syntax.OpAlternate:
		size := int64(len(re.Sub))
		for _, sub := range re.Sub {
			size = sat(size + nodeSize(sub))
		}
		return size
	}
	return 1
}

// prescan reads expr once, before Go parses it, and accepts it only when it
// is written in the forms whose meaning ECMA-262 (JSON Schema's regular
// expressions: Core 2020-12 §6.4 refers to its 11th edition, ES2020) and
// Go's regexp share, but for two, which Go reads its own way: . also
// matches \r, U+2028 and U+2029, which ECMA-262's does not; and \s is the
// ASCII spaces \t \n \f \r and space, where ECMA-262's also holds \v and
// the Unicode spaces (\S is the rest, likewise). Every other form is
// refused, so Go's parser reads only what this scan read, as prescan writes
// it for Go (below). The forms, in valid UTF-8:
//
//   - a character, other than ^ $ \ . * + ? ( ) [ ] { } |; and .
//   - the escapes \d \D \w \W \s \S \b \B, \t \n \v \f \r, \xHH, and a
//     syntax character or / escaped;
//   - \p{Name} and \P{Name}, Name a general category by its short name
//     (unicode.Categories: L, Lu, Nd ...) or by a long name or alias
//     (categoryAliases: Letter, Decimal_Number, digit ...), spelled exactly
//     as ECMA-262 spells them. A category holds the code points Unicode
//     15.0.0 gives it (the pinned tables of internal/ucd), whatever
//     Unicode version the toolchain's unicode package carries;
//   - a class [...] or [^...] of characters, those escapes (\b and \B
//     aside) and \- , and ranges of two characters, the first not after
//     the second; not empty, with no [ inside;
//   - groups (...), (?:...) and (?<name>...), name [A-Za-z_][A-Za-z0-9_]*;
//   - * + ? {n} {n,} {n,m}, each lazy or not, the counts without a leading
//     zero and at most 1000, n not above m, after a character, a class, an
//     escape that matches a character, or a group;
//   - ^ $ |.
//
// Inline flags ((?i), under which Go's parser folds each range of a class
// rune by rune), \Q...\E, POSIX classes, lookarounds and backreferences are
// among what it refuses. It also refuses Unicode classes whose tables hold,
// summed, more than maxPatternSize ranges (counting one more for each
// negated one), and groups nested more than maxGroupDepth deep.
//
// It returns expr as Go's parser is to read it, each Unicode class written
// out as the ranges of its pinned table, so Go's parser does not read a
// category's name: outside a class as a class of its own ([...], or [^...]
// negated); and a class that holds one as the code points the class holds,
// its other members as Go reads them (\d \w \s ASCII), each \P as the code
// points outside its table, all merged. So Go reads for a class at most one
// range more than its program counts (patternSize). Its work is linear in
// expr's length and, for an expression it accepts, in the ranges of its
// Unicode classes (at most maxPatternSize), but for sorting a class's ranges.
func prescan(expr string) (string, int, error) {
	return prescanWithin(expr, maxPatternSize)
}

// errPastTotal refuses an expression that costs more than what is left of a
// schema's total. A cost is counted in instructions, a range of a Unicode
// table read for it counting as one.
var errPastTotal = errors.New("regexp: the schema's regular expressions, together, have more instructions than it is allowed")

// prescanWithin is prescan, refusing too, with errPastTotal, an expression
// whose Unicode classes hold more than room ranges, what is left of a total.
// It reads expr once to check it and count those ranges, and only for an
// expression it accepts reads them again to write them out, so refusing one
// takes time in its length alone.
func prescanWithin(expr string, room int) (string, int, error) {
	_, ranges, err := scanExpr(expr, room, false)
	if err != nil {
		return "", 0, err
	}
	if ranges == 0 {
		return expr, 0, nil
	}
	return scanExpr(expr, room, true)
}

// scanExpr is prescanWithin's reading of expr, writing the Unicode classes out
// when write is set.
func scanExpr(expr string, room int, write bool) (string, int, error) {
	if !utf8.ValidString(expr) {
		return "", 0, errors.New("regexp: not valid UTF-8")
	}
	ranges, depth, quantifiable := 0, 0, false
	// goExpr is expr up to copied, each Unicode class written out: outside a
	// class as a class of its own, and a class that holds one as the code
	// points the class holds (classSet, from all its members), merged.
	var goExpr []byte
	copied := 0
	var classSet [][2]rune
	classHasCategory := false
	// unicodeClass reads the Unicode class at expr[i] (p or P, after a
	// backslash), counts its ranges and writes it out, and returns the index
	// after it.
	unicodeClass := func(i int, withinClass bool) (int, error) {
		j := i + 1
		if j >= len(expr) || expr[j] != '{' {
			return 0, errors.New("regexp: a Unicode class is written \\p{Name}")
		}
		k := strings.IndexByte(expr[j:], '}')
		if k < 0 {
			return 0, errors.New("regexp: a Unicode class is not closed")
		}
		name := expr[j+1 : j+k]
		rs := categoryRanges(name)
		if rs == nil {
			return 0, fmt.Errorf("regexp: %q is not a general category this package accepts", name)
		}
		negated := expr[i] == 'P'
		ranges += len(rs)
		if negated {
			ranges++
		}
		if ranges > maxPatternSize {
			return 0, fmt.Errorf("regexp: its Unicode classes hold more than %d ranges", maxPatternSize)
		}
		if ranges > room {
			return 0, errPastTotal
		}
		end := j + k + 1
		if !write {
			return end, nil
		}
		if !withinClass {
			goExpr = append(goExpr, expr[copied:i-1]...)
			copied = end
			goExpr = append(goExpr, '[')
			if negated {
				goExpr = append(goExpr, '^')
			}
			goExpr = append(appendRanges(goExpr, rs), ']')
			return end, nil
		}
		if negated {
			rs = complement(rs)
		}
		classSet = append(classSet, rs...)
		classHasCategory = true
		return end, nil
	}
	// escape reads the escape at expr[i] (after the backslash), in a class or
	// not; it returns the index after it and the character it stands for, or
	// -1 when it stands for more than one, or for none.
	escape := func(i int, inClass bool) (int, rune, error) {
		if i >= len(expr) {
			return 0, -1, errors.New("regexp: a trailing backslash")
		}
		switch c := expr[i]; c {
		case 'd', 'D', 'w', 'W', 's', 'S':
			if inClass && write {
				classSet = append(classSet, perlClass(c)...)
			}
			return i + 1, -1, nil
		case 'b', 'B':
			if inClass {
				return 0, -1, errors.New("regexp: \\b in a class means different things in ECMA-262 and Go")
			}
			return i + 1, -1, nil
		case 't', 'n', 'v', 'f', 'r':
			return i + 1, map[byte]rune{'t': '\t', 'n': '\n', 'v': '\v', 'f': '\f', 'r': '\r'}[c], nil
		case 'x':
			if i+2 < len(expr) && isHex(expr[i+1]) && isHex(expr[i+2]) {
				v, _ := strconv.ParseUint(expr[i+1:i+3], 16, 8)
				return i + 3, rune(v), nil
			}
			return 0, -1, errors.New("regexp: \\x is followed by two hexadecimal digits")
		case 'p', 'P':
			j, err := unicodeClass(i, inClass)
			return j, -1, err
		case '^', '$', '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '/':
			return i + 1, rune(c), nil
		case '-':
			if inClass {
				return i + 1, '-', nil
			}
		}
		return 0, -1, fmt.Errorf("regexp: the escape \\%c is not one this package accepts", expr[i])
	}
	for i := 0; i < len(expr); {
		switch c := expr[i]; c {
		case '\\':
			j, _, err := escape(i+1, false)
			if err != nil {
				return "", 0, err
			}
			quantifiable = expr[i+1] != 'b' && expr[i+1] != 'B'
			i = j
		case '.':
			quantifiable = true
			i++
		case '^', '$', '|':
			quantifiable = false
			i++
		case '(':
			j := i + 1
			if strings.HasPrefix(expr[j:], "?:") {
				j += 2
			} else if strings.HasPrefix(expr[j:], "?<") {
				k := j + 2
				for k < len(expr) && (expr[k] == '_' || isLetter(expr[k]) || k > j+2 && isDigit(expr[k])) {
					k++
				}
				if k == j+2 || k == len(expr) || expr[k] != '>' {
					return "", 0, errors.New("regexp: a group name is [A-Za-z_][A-Za-z0-9_]*, in (?<name>...)")
				}
				j = k + 1
			} else if strings.HasPrefix(expr[j:], "?") {
				return "", 0, errors.New("regexp: (? begins only (?: or (?<name> here: inline flags such as (?i), and lookarounds, are not accepted")
			}
			depth++
			if depth > maxGroupDepth {
				return "", 0, fmt.Errorf("regexp: its groups nest more than %d deep", maxGroupDepth)
			}
			quantifiable = false
			i = j
		case ')':
			if depth == 0 {
				return "", 0, errors.New("regexp: an unmatched )")
			}
			depth--
			quantifiable = true
			i++
		case '*', '+', '?':
			if !quantifiable {
				return "", 0, fmt.Errorf("regexp: %c follows nothing it can repeat", c)
			}
			i++
			if i < len(expr) && expr[i] == '?' {
				i++
			}
			quantifiable = false
		case '{':
			// A count is written without a leading zero: Go reads {01} as
			// the characters, where ECMA-262 repeats once. Go refuses a
			// count above 1000, and {n,m} with n above m, as ECMA-262 does
			// the latter.
			count := func(j int) (int, int, error) {
				k := j
				for k < len(expr) && isDigit(expr[k]) {
					k++
				}
				if k == j || k > j+1 && expr[j] == '0' {
					return 0, 0, errors.New("regexp: { begins only a repeat, {n}, {n,} or {n,m}, each count without a leading zero")
				}
				if k-j > 4 || k-j == 4 && expr[j:k] > "1000" {
					return 0, 0, errors.New("regexp: a repeat count is at most 1000")
				}
				n, _ := strconv.Atoi(expr[j:k])
				return k, n, nil
			}
			j, least, err := count(i + 1)
			if err != nil {
				return "", 0, err
			}
			if j < len(expr) && expr[j] == ',' {
				if j+1 < len(expr) && isDigit(expr[j+1]) {
					var most int
					if j, most, err = count(j + 1); err != nil {
						return "", 0, err
					}
					if least > most {
						return "", 0, errors.New("regexp: a repeat {n,m} has n at most m")
					}
				} else {
					j++
				}
			}
			if j == len(expr) || expr[j] != '}' {
				return "", 0, errors.New("regexp: { begins only a repeat, {n}, {n,} or {n,m}, each count without a leading zero")
			}
			if !quantifiable {
				return "", 0, errors.New("regexp: a repeat follows nothing it can repeat")
			}
			i = j + 1
			if i < len(expr) && expr[i] == '?' {
				i++
			}
			quantifiable = false
		case '}', ']':
			return "", 0, fmt.Errorf("regexp: an unmatched %c", c)
		case '[':
			classSet, classHasCategory = classSet[:0], false
			j, err := classEnd(expr, i, escape, func(lo, hi rune) {
				if write {
					classSet = append(classSet, [2]rune{lo, hi})
				}
			})
			if err != nil {
				return "", 0, err
			}
			if classHasCategory {
				goExpr = append(goExpr, expr[copied:i]...)
				goExpr = append(goExpr, '[')
				if expr[i+1] == '^' {
					goExpr = append(goExpr, '^')
				}
				goExpr = append(appendRanges(goExpr, union(classSet)), ']')
				copied = j
			}
			quantifiable = true
			i = j
		default:
			_, n := utf8.DecodeRuneInString(expr[i:])
			quantifiable = true
			i += n
		}
	}
	if depth != 0 {
		return "", 0, errors.New("regexp: an unclosed (")
	}
	if copied == 0 {
		return expr, ranges, nil
	}
	return string(append(goExpr, expr[copied:]...)), ranges, nil
}

// classEnd reads the class at expr[i] ('['), and returns the index after it.
// It passes add each character and range among the class's members; escape
// keeps the members that stand for more than one character.
func classEnd(expr string, i int, escape func(int, bool) (int, rune, error), add func(lo, hi rune)) (int, error) {
	j := i + 1
	if j < len(expr) && expr[j] == '^' {
		j++
	}
	if j < len(expr) && expr[j] == ']' {
		return 0, errors.New("regexp: an empty class, or ] first in a class, means different things in ECMA-262 and Go")
	}
	// atom reads one member at j: its end, and the character it is, or -1
	// when it is more than one.
	atom := func(j int) (int, rune, error) {
		switch expr[j] {
		case '\\':
			return escape(j+1, true)
		case '[':
			return 0, -1, errors.New("regexp: [ in a class means different things in ECMA-262 and Go")
		}
		r, n := utf8.DecodeRuneInString(expr[j:])
		return j + n, r, nil
	}
	for j < len(expr) && expr[j] != ']' {
		k, lo, err := atom(j)
		if err != nil {
			return 0, err
		}
		j = k
		if j+1 < len(expr) && expr[j] == '-' && expr[j+1] != ']' {
			k, hi, err := atom(j + 1)
			if err != nil {
				return 0, err
			}
			if lo < 0 || hi < 0 {
				return 0, errors.New("regexp: a range in a class is between two characters")
			}
			if hi < lo {
				return 0, errors.New("regexp: a range in a class ends before it begins")
			}
			add(lo, hi)
			j = k
		} else if lo >= 0 {
			add(lo, lo)
		}
	}
	if j == len(expr) {
		return 0, errors.New("regexp: an unclosed [")
	}
	return j + 1, nil
}

func isHex(c byte) bool    { return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }
func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// categoryAliases are the names of a general category other than its short
// name, each with the short name it names, as ECMA-262 11th edition (ES2020,
// the edition JSON Schema 2020-12 refers to) lists them in Table 57, "Value
// aliases and canonical values for the Unicode property General_Category".
// They, and the short names (ucd.Category), are what a pattern may name;
// prescan reads each as its short name, with the pinned table (the tests
// check the list against the UCD's aliases).
var categoryAliases = map[string]string{
	"Cased_Letter": "LC", "Close_Punctuation": "Pe", "Connector_Punctuation": "Pc",
	"Control": "Cc", "cntrl": "Cc", "Currency_Symbol": "Sc", "Dash_Punctuation": "Pd",
	"Decimal_Number": "Nd", "digit": "Nd", "Enclosing_Mark": "Me", "Final_Punctuation": "Pf",
	"Format": "Cf", "Initial_Punctuation": "Pi", "Letter": "L", "Letter_Number": "Nl",
	"Line_Separator": "Zl", "Lowercase_Letter": "Ll", "Mark": "M", "Combining_Mark": "M",
	"Math_Symbol": "Sm", "Modifier_Letter": "Lm", "Modifier_Symbol": "Sk",
	"Nonspacing_Mark": "Mn", "Number": "N", "Open_Punctuation": "Ps", "Other": "C",
	"Other_Letter": "Lo", "Other_Number": "No", "Other_Punctuation": "Po",
	"Other_Symbol": "So", "Paragraph_Separator": "Zp", "Private_Use": "Co",
	"Punctuation": "P", "punct": "P", "Separator": "Z", "Space_Separator": "Zs",
	"Spacing_Mark": "Mc", "Surrogate": "Cs", "Symbol": "S", "Titlecase_Letter": "Lt",
	"Unassigned": "Cn", "Uppercase_Letter": "Lu",
}

// shortName is the short name of the general category name names, by its
// short name or by a long name or alias spelled exactly (categoryAliases);
// any other name is itself, which no pinned table has.
func shortName(name string) string {
	if short, ok := categoryAliases[name]; ok {
		return short
	}
	return name
}

// categoryRanges is the ranges of the general category name names, in
// order, joined where they touch (a pinned table splits a range at U+FFFF),
// else nil. They are the ranges prescan writes out for the category
// (appendRanges). Each category's are made once and shared: a caller does
// not change them.
func categoryRanges(name string) [][2]rune {
	name = shortName(name)
	if rs, ok := categoryRangeLists.Load(name); ok {
		return rs.([][2]rune)
	}
	t := ucd.Category(name)
	if t == nil {
		return nil
	}
	rs, _ := categoryRangeLists.LoadOrStore(name, mergedRanges(t))
	return rs.([][2]rune)
}

// categoryRangeLists holds categoryRanges' lists, by short name.
var categoryRangeLists sync.Map

// mergedRanges is t's ranges, which are in order with stride 1, joined where
// they touch.
func mergedRanges(t *unicode.RangeTable) [][2]rune {
	var rs [][2]rune
	add := func(lo, hi rune) {
		if n := len(rs); n > 0 && rs[n-1][1]+1 == lo {
			rs[n-1][1] = hi
			return
		}
		rs = append(rs, [2]rune{lo, hi})
	}
	for _, r := range t.R16 {
		add(rune(r.Lo), rune(r.Hi))
	}
	for _, r := range t.R32 {
		add(rune(r.Lo), rune(r.Hi))
	}
	return rs
}

// appendRanges appends rs to b as members of a class Go's parser reads:
// lo-hi, or lo alone. A rune is written as itself, but as \x{hex} where a
// class would read it otherwise (\ ] [ - ^), where it is a control character
// (C0 or C1), and where it is a surrogate, which UTF-8 cannot hold.
func appendRanges(b []byte, rs [][2]rune) []byte {
	appendRune := func(b []byte, r rune) []byte {
		if r < 0x20 || 0x7F <= r && r <= 0x9F || 0xD800 <= r && r <= 0xDFFF || strings.ContainsRune(`\]-[^`, r) {
			b = append(b, `\x{`...)
			b = strconv.AppendInt(b, int64(r), 16)
			return append(b, '}')
		}
		return utf8.AppendRune(b, r)
	}
	for _, r := range rs {
		b = appendRune(b, r[0])
		if r[1] != r[0] {
			b = appendRune(append(b, '-'), r[1])
		}
	}
	return b
}

// union is the ranges of the code points in any of rs, in order, joined
// where they touch.
func union(rs [][2]rune) [][2]rune {
	slices.SortFunc(rs, func(a, b [2]rune) int { return int(a[0] - b[0]) })
	var out [][2]rune
	for _, r := range rs {
		if n := len(out); n > 0 && r[0] <= out[n-1][1]+1 {
			out[n-1][1] = max(out[n-1][1], r[1])
			continue
		}
		out = append(out, r)
	}
	return out
}

// perlClass is the ranges of \d \D \w \W \s or \S (by its letter c) as
// Go's regexp reads them: ASCII digits, word characters, and \t \n \f \r
// and space; an upper-case letter is the code points outside them.
func perlClass(c byte) [][2]rune {
	var rs [][2]rune
	switch c | 0x20 {
	case 'd':
		rs = [][2]rune{{'0', '9'}}
	case 'w':
		rs = [][2]rune{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}
	case 's':
		rs = [][2]rune{{'\t', '\n'}, {'\f', '\r'}, {' ', ' '}}
	}
	if c < 'a' {
		return complement(rs)
	}
	return rs
}

// complement is the ranges of the code points, U+0000 to U+10FFFF, not in
// rs, which are in order and apart.
func complement(rs [][2]rune) [][2]rune {
	var out [][2]rune
	next := rune(0)
	for _, r := range rs {
		if r[0] > next {
			out = append(out, [2]rune{next, r[0] - 1})
		}
		next = r[1] + 1
	}
	if next <= unicode.MaxRune {
		out = append(out, [2]rune{next, unicode.MaxRune})
	}
	return out
}
