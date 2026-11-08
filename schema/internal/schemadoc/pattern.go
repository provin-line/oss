package schemadoc

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/provin-line/oss/internal/jsonschema"
)

// maxPatternSize bounds every regular expression the library compiles here
// (a schema's pattern and patternProperties names, and a payload value
// checked as format "regex") by the size of its program: patternSize, the
// instructions once its repeats are expanded, each character class counted
// with its ranges. Go's regexp compiles a program in time and memory linear
// in that size (at most about 150 ns and 150 bytes per instruction,
// measured, without the one-pass analysis: onePassGuard), and matches a
// position against it in time at most linear in it. The 1,029 schemas of
// SchemaStore hold no pattern above 5,415.
const maxPatternSize = 8192

// maxGroupDepth bounds how deep an expression's groups nest. Go's parser
// copies what a non-capturing group holds into the concatenation around it,
// at each level, so parsing takes time and memory in the expression's length
// times that depth: at 32, at most about 120 ns and 110 bytes per byte
// (measured), two to three times an expression without groups. The 8,237
// patterns of SchemaStore nest at most 7 deep.
const maxGroupDepth = 32

// compileRegexpWithin compiles expr with Go's regexp, refusing, before it
// parses it, what would make parsing it take more than time and memory
// linear in its length and maxPatternSize (prescan), and before it compiles
// it, a program larger than maxPatternSize or, when left is not nil, than
// what is left of a total, which it then takes. It says the size of the
// program it compiles (sizedRegexp), by which the library charges matching
// and compiling it.
func compileRegexpWithin(expr string, left *int64) (jsonschema.Regexp, error) {
	if err := prescan(expr); err != nil {
		return nil, err
	}
	parsed, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	n := patternSize(parsed) + onePassGuardSize
	if n > maxPatternSize {
		return nil, fmt.Errorf("regexp: its program has more than %d instructions", maxPatternSize)
	}
	if left != nil {
		if n > *left {
			return nil, errors.New("regexp: the schema's regular expressions, together, have more instructions than it is allowed")
		}
		*left -= n
	}
	re, err := regexp.Compile(onePassGuard + "(?:" + expr + ")")
	if err != nil {
		return nil, err
	}
	return sizedRegexp{re, expr, int(n)}, nil
}

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
// expressions one Compile compiles, by their sizes summed (patternSize, each
// expression counted each time it is compiled: a pattern is compiled again
// where the metaschema checks it as format "regex", as the metaschemas of
// every draft are compiled asserting formats). A
// schema of b bytes may compile patternTotalBase + b/4 instructions: one
// pattern of maxPatternSize twice, and one instruction per 4 bytes past
// that. Go's regexp allocates about 150 bytes per instruction it compiles,
// so compiling them allocates at most about (2^14 + b/4) × 150 bytes: about
// 40 MB for a schema of 1 MiB.
//
// The values are measured. Of the 1,029 schemas of SchemaStore, the 882 that
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
		return compileRegexpWithin(expr, nil)
	}
	return compileRegexpWithin(expr, &t.left)
}

// sizedRegexp is a compiled regular expression, the expression it was
// compiled from, and the size of its program.
type sizedRegexp struct {
	*regexp.Regexp
	expr string
	size int
}

// String is the expression as the schema or the payload wrote it.
func (r sizedRegexp) String() string { return r.expr }

// Size is the size of the program, which the library charges per byte
// matched (jsonschema.PatternInstructionsPerStep) and once per value
// compiled as format "regex".
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
// refused, so Go's parser reads only what this scan read. The forms, in
// valid UTF-8:
//
//   - a character, other than ^ $ \ . * + ? ( ) [ ] { } |; and .
//   - the escapes \d \D \w \W \s \S \b \B, \t \n \v \f \r, \xHH, and a
//     syntax character or / escaped;
//   - \p{Name} and \P{Name}, Name a general category of Go's tables
//     (unicode.Categories: L, Lu, Nd ...), which ECMA-262 names alike;
//   - a class [...] or [^...] of characters, those escapes (\b and \B
//     aside) and \- , and ranges of two characters, the first not after
//     the second; not empty, with no [ inside;
//   - groups (...), (?:...) and (?<name>...), name [A-Za-z_][A-Za-z0-9_]*;
//   - * + ? {n} {n,} {n,m}, each lazy or not, the counts without a leading
//     zero, after a character, a class, an escape that matches a character,
//     or a group;
//   - ^ $ |.
//
// Inline flags ((?i), under which Go's parser folds each range of a class
// rune by rune), \Q...\E, POSIX classes, lookarounds and backreferences are
// among what it refuses. It also refuses Unicode classes whose tables hold,
// summed, more than maxPatternSize ranges, as Go's parser copies them, and
// groups nested more than maxGroupDepth deep. Its work is linear in expr's
// length.
func prescan(expr string) error {
	if !utf8.ValidString(expr) {
		return errors.New("regexp: not valid UTF-8")
	}
	ranges, depth, quantifiable := 0, 0, false
	unicodeClass := func(i int) (int, error) { // expr[i] is p or P; returns the index after the class
		j := i + 1
		if j >= len(expr) || expr[j] != '{' {
			return 0, errors.New("regexp: a Unicode class is written \\p{Name}")
		}
		k := strings.IndexByte(expr[j:], '}')
		if k < 0 {
			return 0, errors.New("regexp: a Unicode class is not closed")
		}
		name := expr[j+1 : j+k]
		if _, ok := unicode.Categories[name]; !ok {
			return 0, fmt.Errorf("regexp: %q is not a general category this package accepts", name)
		}
		ranges += unicodeClassRanges(name)
		if expr[i] == 'P' {
			ranges++
		}
		if ranges > maxPatternSize {
			return 0, fmt.Errorf("regexp: its Unicode classes hold more than %d ranges", maxPatternSize)
		}
		return j + k + 1, nil
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
			j, err := unicodeClass(i)
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
				return err
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
					return errors.New("regexp: a group name is [A-Za-z_][A-Za-z0-9_]*, in (?<name>...)")
				}
				j = k + 1
			} else if strings.HasPrefix(expr[j:], "?") {
				return errors.New("regexp: (? begins only (?: or (?<name> here: inline flags such as (?i), and lookarounds, are not accepted")
			}
			depth++
			if depth > maxGroupDepth {
				return fmt.Errorf("regexp: its groups nest more than %d deep", maxGroupDepth)
			}
			quantifiable = false
			i = j
		case ')':
			if depth == 0 {
				return errors.New("regexp: an unmatched )")
			}
			depth--
			quantifiable = true
			i++
		case '*', '+', '?':
			if !quantifiable {
				return fmt.Errorf("regexp: %c follows nothing it can repeat", c)
			}
			i++
			if i < len(expr) && expr[i] == '?' {
				i++
			}
			quantifiable = false
		case '{':
			// A count is written without a leading zero: Go reads {01} as
			// the characters, where ECMA-262 repeats once.
			count := func(j int) (int, bool) {
				k := j
				for k < len(expr) && isDigit(expr[k]) {
					k++
				}
				return k, k == j+1 || k > j && expr[j] != '0'
			}
			j, ok := count(i + 1)
			if !ok {
				return errors.New("regexp: { begins only a repeat, {n}, {n,} or {n,m}, each count without a leading zero")
			}
			if j < len(expr) && expr[j] == ',' {
				if j+1 < len(expr) && isDigit(expr[j+1]) {
					if j, ok = count(j + 1); !ok {
						return errors.New("regexp: { begins only a repeat, {n}, {n,} or {n,m}, each count without a leading zero")
					}
				} else {
					j++
				}
			}
			if j == len(expr) || expr[j] != '}' {
				return errors.New("regexp: { begins only a repeat, {n}, {n,} or {n,m}, each count without a leading zero")
			}
			if !quantifiable {
				return errors.New("regexp: a repeat follows nothing it can repeat")
			}
			i = j + 1
			if i < len(expr) && expr[i] == '?' {
				i++
			}
			quantifiable = false
		case '}', ']':
			return fmt.Errorf("regexp: an unmatched %c", c)
		case '[':
			j, err := classEnd(expr, i, escape)
			if err != nil {
				return err
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
		return errors.New("regexp: an unclosed (")
	}
	return nil
}

// classEnd reads the class at expr[i] ('['), and returns the index after it.
func classEnd(expr string, i int, escape func(int, bool) (int, rune, error)) (int, error) {
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
			j = k
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

// unicodeClassRanges is the ranges Go's parser puts in a class for the
// general category name (prescan counts one more for a negated class): one
// per range of its table, or one per rune of a range whose stride is not 1.
// A name that is not a general category counts none; prescan refuses it.
func unicodeClassRanges(name string) int {
	t := unicode.Categories[name]
	if t == nil {
		return 0
	}
	n := 0
	for _, r := range t.R16 {
		n += strideRanges(uint32(r.Lo), uint32(r.Hi), uint32(r.Stride))
	}
	for _, r := range t.R32 {
		n += strideRanges(r.Lo, r.Hi, r.Stride)
	}
	return n
}

func strideRanges(lo, hi, stride uint32) int {
	if stride <= 1 {
		return 1
	}
	return int((hi-lo)/stride + 1)
}
