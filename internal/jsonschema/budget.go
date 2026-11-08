// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema

// Work budget: a patch to v6.0.3. This file and the lines marked "work
// budget" in validator.go, util.go, vocab.go, roots.go, objcompiler.go and
// schema.go are not upstream code (README.md, patches/work-budget.patch).

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/message"
)

// MaxNesting is how deeply ValidateWithBudget applies schemas within one
// another: each $ref, applicator and value below another adds a level, and
// each level holds stack.
const MaxNesting = 10_000

// PatternInstructionsPerStep is how many instructions of a pattern's
// program cost one more step per byte matched, when the RegexpEngine's
// Regexp says its size (a Size() int method): matching a byte against a
// program takes time in its size.
const PatternInstructionsPerStep = 16

// patternSize is the size of re's program as the RegexpEngine's Regexp gives
// it (a Size() int method), or 0 when it gives none or a negative one.
func patternSize(re Regexp) int {
	if s, ok := re.(interface{ Size() int }); ok {
		return max(s.Size(), 0)
	}
	return 0
}

// product is a × b steps, for a and b of at least 0, in int64 as the budget
// counts, saturating at the largest int64 instead of overflowing, so it
// exceeds any budget.
func product(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

// compileRegexFormat checks format "regex" as engine compiles v. Before the
// engine runs, it spends PatternParseStepsPerByte steps per byte of v, and
// does not run the engine when the budget cannot pay them. After, it spends
// PatternCompileStepsPerInstruction steps per instruction of the program
// compiled, whose size is known only then: once the budget is spent, at
// most this one compile has run past it, within the engine's own bounds. A
// value the engine refuses spends only the steps of its bytes.
func (vd *validator) compileRegexFormat(engine RegexpEngine, v any) error {
	str, ok := v.(string)
	if !ok {
		return nil
	}
	if !vd.budget.spendSteps(product(PatternParseStepsPerByte, int64(len(str)))) {
		return nil
	}
	re, err := engine(str)
	if err != nil {
		return err
	}
	vd.budget.spendSteps(product(PatternCompileStepsPerInstruction, int64(patternSize(re))))
	return nil
}

// sortSteps is the steps of sorting obj's names: n log n for n names
// (n × (1 + bits.Len(n))), and one per byte of each.
func sortSteps(obj map[string]any) int64 {
	n := int64(len(obj))
	steps := product(n, 1+int64(bits.Len64(uint64(n))))
	for name := range obj {
		steps += int64(len(name))
	}
	return steps
}

// sortedNames is obj's names in order, spending sortSteps(obj) steps of b
// first. It reports false when b cannot pay them.
func sortedNames(b *workBudget, obj map[string]any) ([]string, bool) {
	if !b.spendSteps(sortSteps(obj)) {
		return nil, false
	}
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, true
}

// numberSteps is the steps of reading a number written as text as an exact
// rational: one per byte, and one per unit of its exponent, as reading it
// builds that power of ten. An exponent too long to read is more steps than
// any budget.
func numberSteps(text string) int64 {
	n := int64(len(text))
	i := strings.IndexAny(text, "eE")
	if i < 0 {
		return n
	}
	exp, err := strconv.ParseInt(text[i+1:], 10, 64)
	if err != nil || exp == math.MinInt64 {
		return math.MaxInt64
	}
	exp = max(exp, -exp)
	if exp > math.MaxInt64-n {
		return math.MaxInt64
	}
	return n + exp
}

// boundSteps is the steps of comparing a number written as text with bound,
// or dividing one by the other: two, and one per 16 bits of the two. The
// text is taken as 8 bits per step of reading it (numberSteps), more than
// the 3.33 of a decimal digit or of a unit of an exponent, so it is charged
// before it is read.
func boundSteps(text string, bound *big.Rat) int64 {
	read := product(8, numberSteps(text))
	if read == math.MaxInt64 {
		return math.MaxInt64
	}
	return 2 + (read+int64(bound.Num().BitLen()+bound.Denom().BitLen()))/16
}

// spendNumber spends the steps numValidate takes on v, before it reads v:
// reading it (numberSteps), and comparing it with each bound the schema has
// or dividing it by multipleOf (boundSteps). It reports false when the
// budget cannot pay them.
func (vd *validator) spendNumber(v any) bool {
	s := vd.sch
	var text string
	var steps int64
	for _, bound := range []*big.Rat{s.Minimum, s.Maximum, s.ExclusiveMinimum, s.ExclusiveMaximum, s.MultipleOf} {
		if bound == nil {
			continue
		}
		if text == "" {
			text = fmt.Sprintf("%v", v)
			steps = numberSteps(text)
		}
		steps = sumSteps(steps, boundSteps(text, bound))
	}
	return vd.budget.spendSteps(steps)
}

// sumSteps is a + b steps, for a and b of at least 0, saturating at the
// largest int64 as product does.
func sumSteps(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// namesLookedUp is the steps of looking up names in an object: one each,
// and one per byte, which the lookup hashes.
func namesLookedUp(names []string) int64 {
	var n int64
	for _, name := range names {
		n += 1 + int64(len(name))
	}
	return n
}

// PatternParseStepsPerByte is how many steps each byte of a value checked as
// format "regex" costs before it is compiled: parsing takes time in its
// length, whatever the size of the program it compiles to.
const PatternParseStepsPerByte = 4

// PatternCompileStepsPerInstruction is how many steps each instruction of a
// program costs when a value checked as format "regex" is compiled, when the
// RegexpEngine's Regexp says its size: compiling takes time in the size.
const PatternCompileStepsPerInstruction = 4

// BudgetExceededError is returned by ValidateWithBudget when validating a
// value would take more work than the budget it was given, or would nest
// deeper than MaxNesting, and by CompileWithBudget when checking a schema
// against its metaschema would.
type BudgetExceededError struct {
	// Budget is the number of steps the validation was given.
	Budget int64
	// Nested reports that the validation would have nested deeper than
	// MaxNesting, whatever its steps.
	Nested bool
}

func (e *BudgetExceededError) Error() string {
	if e.Nested {
		return fmt.Sprintf("jsonschema: validation nests schemas deeper than %d", MaxNesting)
	}
	return fmt.Sprintf("jsonschema: validation needs more than its work budget of %d steps", e.Budget)
}

// ValidateWithBudget validates v as Validate does, within budget steps of
// work. A step is:
//
//   - one schema applied to one value; one property (and one per byte of its
//     name), item or string byte of that value;
//   - one patternProperties pattern tried against a property name, and one
//     per byte of the name;
//   - PatternParseStepsPerByte per byte of each value compiled as format
//     "regex", before it is compiled;
//   - when the RegexpEngine's Regexp says the size n of its program (a
//     Size() int method): n/PatternInstructionsPerStep more per position (each
//     byte, and the end) of a string a pattern or a patternProperties
//     pattern is matched against, and PatternCompileStepsPerInstruction × n
//     for each value it compiles as format "regex";
//   - reading a number, for a bound, for type integer, or to compare or
//     hash it: one step per byte of its text and one per unit of its
//     exponent; and comparing it with each bound or dividing it by
//     multipleOf: two, and one per 16 bits of the two numbers (its own
//     taken as 8 per step of reading it);
//   - one name of required, dependentRequired or dependencies looked up, and
//     one entry of dependencies, dependentSchemas or dependentRequired, each
//     with one per byte of the name;
//   - one scope walked to detect a cycle or to resolve $recursiveRef or
//     $dynamicRef;
//   - one token of a value's location copied into an error;
//   - when enum, const or uniqueItems compares or hashes values: one value
//     visited, one byte of each string, property name or number text it
//     reads, one item uniqueItems looks at, and the sort of an object's
//     names it compares or hashes (n log n steps for n names, and their
//     bytes; names that share a long prefix take more per comparison, up to
//     a factor of log n).
//
// When validation would take more steps than budget, or would apply schemas
// within one another more than MaxNesting deep (counting on through the
// validations propertyNames and contentSchema start), it stops (every step
// after that stops at once, and so does every loop around it) and
// ValidateWithBudget returns a *BudgetExceededError, never a result from the
// work it did not finish. A budget of 0 or less admits no step. Applying a
// schema to a value reads the value's names or items once to count them, and
// sets up the tracking of what it evaluates, before it checks the budget:
// so each application that starts reads that much of its value, counted or
// not.
//
// The budget counts the work of this package's validator, and the
// validations and comparisons a custom vocabulary asks of its
// ValidatorContext. It does not count, beyond the length of what they read:
//
//   - a custom vocabulary's own work;
//   - a RegexpEngine's parsing, matching and compiling, beyond what the
//     length of what it reads and its Regexp's size charge, and a format
//     check (format "regex" compiles the string; format is asserted where a
//     schema's draft or the compiler asks for it).
//
// Bound the depth of v before validating it. Compiling schemas is counted by
// (*Compiler).CompileWithBudget, which checks them against their
// metaschemas within a budget of these steps.
func (sch *Schema) ValidateWithBudget(v any, budget int64) error {
	b := &workBudget{left: budget}
	err := sch.validate(v, nil, nil, nil, false, nil, b, 0)
	if b.exceeded || budget <= 0 {
		return &BudgetExceededError{Budget: budget, Nested: b.nested}
	}
	return err
}

// workBudget is the steps left in one ValidateWithBudget call, shared by
// every validator it creates. A nil *workBudget is unlimited.
type workBudget struct {
	left     int64
	exceeded bool
	nested   bool // exceeded by nesting deeper than MaxNesting
}

// spend takes n steps, and reports false once the budget is exceeded. Once
// exceeded, it stays so, so every later step stops at once. A negative n,
// which no charge is, exceeds it.
func (b *workBudget) spend(n int) bool { return b.spendSteps(int64(n)) }

// spendSteps is spend for a charge counted in int64 (product).
func (b *workBudget) spendSteps(n int64) bool {
	if b == nil {
		return true
	}
	if b.exceeded || n < 0 || n > b.left {
		b.left, b.exceeded = 0, true
		return false
	}
	b.left -= n
	return true
}

// nest reports false, and exceeds the budget, once depth is beyond
// MaxNesting. A nil budget is unlimited.
func (b *workBudget) nest(depth int) bool {
	if b == nil || depth <= MaxNesting {
		return true
	}
	b.left, b.exceeded, b.nested = 0, true, true
	return false
}

// over reports whether the budget is exceeded. A validator checks it before
// any work that depends on its value, and then does none.
func (b *workBudget) over() bool {
	return b != nil && b.exceeded
}

// errBudget is the error a validator stops with once its budget is exceeded:
// a new one each time, without a location, since callers may change it.
func errBudget() *ValidationError {
	return &ValidationError{ErrorKind: budgetExceeded{}}
}

// workOf is the steps for applying one schema to v, besides the one for the
// schema itself: what the validator iterates or reads of v.
func workOf(v any) int {
	switch v := v.(type) {
	case map[string]any:
		n := len(v)
		for k := range v {
			n += len(k)
		}
		return n
	case []any:
		return len(v)
	case string:
		return len(v)
	}
	return 0
}

// budgetExceeded is the error kind a validator stops with once its budget is
// exceeded. ValidateWithBudget reports a *BudgetExceededError instead.
type budgetExceeded struct{}

func (budgetExceeded) KeywordPath() []string { return nil }

func (budgetExceeded) LocalizedString(p *message.Printer) string {
	return p.Sprintf("validation work budget exceeded")
}
