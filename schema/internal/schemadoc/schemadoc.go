// Package schemadoc is the single JSON Schema policy shared by the
// schema-registry admission check (schema.ValidateJSONSchema) and the in-memory
// validator implementation (schema/local): strict-decode every document the
// library reads, schema or payload (the only JSON decode path permitted on
// protocol boundaries — duplicate keywords, trailing data and invalid Unicode
// are rejected), refuse a number the library would read slowly, pin the
// dialect to Draft 2020-12 (the library's default tracks "latest supported"
// and shifts), deny external $ref so a schema is self-contained as a
// structural guarantee, and bound the library's work on a payload by a budget
// that grows with the payload's size. A payload reaches the library only
// through Schema.Validate, which decodes it first.
//
// The library is internal/jsonschema, a copy of santhosh-tekuri/jsonschema
// with a work budget added, and an error for a number it cannot read where
// upstream panics (its README.md).
//
// Internal: this is an implementation detail, not part of the public API. The
// public entry points are schema.ValidateJSONSchema (admission) and the
// schema.Validator implementations.
package schemadoc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/provin-line/oss/internal/jsonschema"
	"github.com/provin-line/oss/internal/jsonschema/kind"

	"github.com/provin-line/oss/canon"
)

// denyLoader makes "self-contained schema" a STRUCTURAL guarantee rather than a
// convention: any external $ref (file://, http(s)://, …) fails closed at
// compile time. Without it the library's default FileLoader would read local
// files referenced by a crafted $ref — a local-file-inclusion vector in a layer
// whose threat model already assumes adversarially modified schemas. Internal
// ("#/…") refs and refs to the resource being compiled do not hit the loader.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schemadoc: external $ref is not allowed: %s", url)
}

// resourceID is where Compile compiles every document. External $ref is
// denied and internal ("#/…") refs resolve against the document being
// compiled, so the base URI is immaterial, and one fixed URN keeps the
// compile the same for every caller: the library skips the metaschema check
// for a document whose location is below json-schema.org.
const resourceID = "urn:dplaax:schema-doc:document"

// Compile strict-decodes document, pins Draft 2020-12, denies external $ref, and
// returns the compiled schema. It is the one policy point: callers that need
// the compiled schema (the validator's Add) and callers that only need the
// well-formedness verdict (Validate) share it, so the admission policy cannot
// drift between them.
func Compile(document []byte) (*Schema, error) {
	doc, _, err := decode(document)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	patterns := newPatternTotal(len(document))
	c.UseRegexpEngine(patterns.compile)
	// Content assertion stays off (the library's default): with it, the
	// library would decode a contentMediaType "application/json" string
	// itself, outside decode.
	if err := c.AddResource(resourceID, doc); err != nil {
		return nil, fmt.Errorf("schemadoc: add resource: %w", err)
	}
	compiled, err := c.Compile(resourceID)
	patterns.compiled = true
	if err != nil {
		return nil, fmt.Errorf("schemadoc: compile: %w", err)
	}
	return &Schema{compiled: compiled}, nil
}

// Schema is a compiled schema.
type Schema struct {
	compiled *jsonschema.Schema
}

// The library's work on a payload is not bounded by the payload's size alone:
// a recursive schema, an applicator or a $ref applies schemas to a value
// again, and enum, const and uniqueItems compare values. Validate gives it a
// budget of budgetBase steps plus budgetPerByte steps per byte of the
// payload (ValidateWithBudget states what a step is). Two ordinary schemas
// took 1.0 and 1.6 steps per byte at 9–17 ns a step (internal/jsonschema's
// BenchmarkValidateWithBudget), so the budget is many times an ordinary
// validation. Each schema applied to a value charges the value's size, so
// schemas layered on one value (allOf, $ref) take more.
//
// A number is charged by its text and its exponent when it is read, and by
// its size and a bound's when it is compared with the bound or divided by
// multipleOf; within decode's bounds on numbers, such a step takes at most
// about 50 ns (measured), as applying a schema through $ref does. What the
// budget does not count is kept small here: the library's work per step
// grows with nesting, so a payload is refused when it is nested deeper than
// maxPayloadDepth. The error names the bound.
//
// A regular expression is parsed here only when it is written in the forms
// ECMA-262 and Go's regexp read alike (but for . and \s, which Go reads its
// own way), its groups nested at most 32 deep (prescan, which reads it
// once), so Go parses it in time linear in its length; compiled only within
// a size n of maxPatternSize (8,192, an upper bound of its instructions;
// compileRegexpWithin); and charged by its length and n. Matching one
// position of a string (each byte, and the end) against it costs n/16 steps
// besides the byte's own (16 being jsonschema.PatternInstructionsPerStep).
// Compiling a payload value as format "regex" costs 4 steps per byte before
// (jsonschema.PatternParseStepsPerByte) and 4n after
// (jsonschema.PatternCompileStepsPerInstruction). Go's regexp matches a
// position in at most about 7 ns × n (measured: every NFA thread alive),
// parses and compiles an expression in at most about 240 ns per byte
// (measured: groups 31 deep in a body repeated {0} times, parsed twice), and
// compiles an instruction in at most about 150 ns, never analysing a program
// as one-pass here (onePassGuard; measured). So a step of matching takes at
// most about 16 × 7 ns ≈ 112 ns, one of parsing about 60 ns and one of
// compiling about 40 ns; other steps take 9–50 ns (the most where a schema
// is applied through $ref). The time of a validation is at most about
// 112 ns × its budget. SchemaStore's 1,298 valid examples, against the
// schemas that compile here, need at most 98 steps per byte, and none more
// than its budget.
const (
	budgetBase      = 1 << 20
	budgetPerByte   = 16
	maxPayloadDepth = 512
)

// Validate decodes payload as Compile decodes a schema (strictly, within the
// number bounds) and validates it against the schema within its work budget.
// A payload that needs more work, or that would apply schemas within one
// another deeper than jsonschema.MaxNesting, is refused, the error naming
// the bound.
func (s *Schema) Validate(payload []byte) error {
	inst, depth, err := decode(payload)
	if err != nil {
		return err
	}
	if depth > maxPayloadDepth {
		return fmt.Errorf("schemadoc: payload nested %d deep, beyond the bound of %d levels", depth, maxPayloadDepth)
	}
	budget := budgetBase + budgetPerByte*int64(len(payload))
	err = s.compiled.ValidateWithBudget(inst, budget)
	var exceeded *jsonschema.BudgetExceededError
	switch {
	case errors.As(err, &exceeded) && exceeded.Nested:
		return fmt.Errorf("schemadoc: validating the payload nests schemas deeper than %d", jsonschema.MaxNesting)
	case errors.As(err, &exceeded):
		return fmt.Errorf("schemadoc: validating the payload needs more than its work budget of %d steps (%d, and %d per byte of payload)", exceeded.Budget, budgetBase, budgetPerByte)
	case err != nil:
		return fmt.Errorf("schemadoc: does not conform: %s", firstFailure(err))
	}
	return nil
}

// maxFailureBytes bounds the text of a conformance error.
const maxFailureBytes = 1 << 10

// printer writes the library's descriptions of a failure.
var printer = message.NewPrinter(language.English)

// pointerEscaper escapes a token of a JSON pointer (RFC 6901).
var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

// firstFailure states the first place the payload fails to conform, within
// maxFailureBytes: where it is in the payload, the keyword it fails, and the
// library's description of the failure when that grows only with the payload
// or with numbers within the bounds every schema keeps (described). The
// library's own text lists every failure, and its description of a keyword
// such as required, enum, const or pattern quotes what the schema holds, so
// on every failed validation it would take work in the size of the schema;
// neither is built. The text is cut while it is written.
func firstFailure(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return cutFailure(err.Error())
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	var b strings.Builder
	b.WriteString("at '")
	for _, tok := range ve.InstanceLocation {
		writeWithin(&b, "/")
		writeEscaped(&b, pointerEscaper.Replace(tok), true)
	}
	writeWithin(&b, "': ")
	switch {
	case ve.ErrorKind == nil:
		writeWithin(&b, "fails the schema")
	case described(ve.ErrorKind):
		writeEscaped(&b, ve.ErrorKind.LocalizedString(printer), false)
	default:
		writeWithin(&b, "fails ")
		if path := ve.ErrorKind.KeywordPath(); len(path) > 0 {
			for i, kw := range path {
				if i > 0 {
					writeWithin(&b, "/")
				}
				writeEscaped(&b, kw, true)
			}
		} else {
			writeWithin(&b, unnamed(ve.ErrorKind))
		}
	}
	return cutFailure(b.String())
}

// described reports whether the library's description of k grows only with
// the payload, or with numbers within the bounds every schema keeps (a type
// name, a count, a number, a format's name).
func described(k jsonschema.ErrorKind) bool {
	switch k.(type) {
	case *kind.Type, *kind.FalseSchema, *kind.InvalidJsonValue, *kind.LargeNumber,
		*kind.Not, *kind.AllOf, *kind.AnyOf, *kind.OneOf, *kind.Contains, *kind.AdditionalItems,
		*kind.Reference, *kind.Group,
		*kind.Minimum, *kind.Maximum, *kind.ExclusiveMinimum, *kind.ExclusiveMaximum, *kind.MultipleOf,
		*kind.MinLength, *kind.MaxLength, *kind.MinItems, *kind.MaxItems,
		*kind.MinProperties, *kind.MaxProperties, *kind.MinContains, *kind.MaxContains,
		*kind.UniqueItems, *kind.Format, *kind.AdditionalProperties, *kind.PropertyNames:
		return true
	}
	return false
}

// unnamed names, in words, a failure that has no keyword path and is not
// described: a $ref cycle (whose description quotes locations in the
// schema), or the schema as a whole.
func unnamed(k jsonschema.ErrorKind) string {
	if _, ok := k.(*kind.RefCycle); ok {
		return "a $ref cycle"
	}
	return "the schema"
}

// writeWithin writes s to b, as much of it as keeps b within one byte past
// maxFailureBytes, where cutFailure cuts it.
func writeWithin(b *strings.Builder, s string) {
	room := maxFailureBytes + 1 - b.Len()
	if room <= 0 {
		return
	}
	if len(s) > room {
		s = s[:room]
	}
	b.WriteString(s)
}

// writeEscaped writes s to b as writeWithin does, with each character that
// is not printable written as Go escapes it (strconv.QuoteRune), and in a
// name a quote and a backslash too: so neither a name from the payload or the
// schema nor a description that quotes the payload (a format check's error)
// can carry a line break or a terminal sequence into the text.
func writeEscaped(b *strings.Builder, s string, name bool) {
	for _, r := range s {
		if b.Len() > maxFailureBytes {
			return
		}
		if strconv.IsPrint(r) && !(name && (r == '\'' || r == '\\')) {
			writeWithin(b, string(r))
			continue
		}
		q := strconv.QuoteRune(r)
		writeWithin(b, q[1:len(q)-1])
	}
}

// cutFailure cuts text to maxFailureBytes, where a character starts, and
// marks the cut with "…".
func cutFailure(text string) string {
	if len(text) <= maxFailureBytes {
		return text
	}
	n := maxFailureBytes
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n] + "…"
}

// The library reads every number as an exact rational (math/big), at a cost
// that grows with the number's length and steeply with its exponent: 1e999999
// alone took about 10 ms, so a few kilobytes of such numbers cost seconds, and
// one whose exponent is beyond ±10^6 it cannot read at all: it drops a schema
// bound holding one, and fails a payload number as an ordinary assertion,
// which "not" inverts and "if" steers on. A number it reads is therefore at
// most maxNumberBytes long, and its exponent part
// (after "e" or "E"), if any, lies within ±maxExponent, beyond binary64's
// range (about 1e±308) with room to spare. Within these bounds a number costs
// it a few microseconds.
const (
	maxNumberBytes = 256
	maxExponent    = 400
)

// decode strict-decodes document, refuses a number beyond the bounds the
// library reads in bounded time (maxNumberBytes, maxExponent), and measures
// the depth of its deepest value (a scalar at the top is depth 1). Compile
// and Schema.Validate decode every JSON value the library reads here.
func decode(document []byte) (any, int, error) {
	var v any
	if err := canon.NewStrictDecoder(document).Decode(&v); err != nil {
		return nil, 0, fmt.Errorf("schemadoc: not strict-decodable JSON: %w", err)
	}
	depth := 0
	if err := walk(v, 1, &depth); err != nil {
		return nil, 0, err
	}
	return v, depth, nil
}

// walk checks every number in v and records the deepest depth.
func walk(v any, at int, depth *int) error {
	*depth = max(*depth, at)
	switch t := v.(type) {
	case map[string]any:
		for _, e := range t {
			if err := walk(e, at+1, depth); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := walk(e, at+1, depth); err != nil {
				return err
			}
		}
	case json.Number:
		return checkNumber(string(t))
	}
	return nil
}

func checkNumber(n string) error {
	if len(n) > maxNumberBytes {
		return fmt.Errorf("schemadoc: a number of %d bytes, beyond %d (%.32s…)", len(n), maxNumberBytes, n)
	}
	i := strings.IndexAny(n, "eE")
	if i < 0 {
		return nil
	}
	// The strict decoder admits only RFC 8259 numbers, so what follows the
	// "e" is an optionally signed run of digits; one too long for int64 is
	// beyond the bound too.
	exp, err := strconv.ParseInt(n[i+1:], 10, 64)
	if err != nil || exp > maxExponent || exp < -maxExponent {
		return fmt.Errorf("schemadoc: number %s: exponent beyond ±%d", n, maxExponent)
	}
	return nil
}

// Validate reports whether document is a well-formed, self-contained JSON Schema:
// it must strict-decode, compile under Draft 2020-12, and reference no external
// $ref. It registers nothing and resolves no reference.
func Validate(document []byte) error {
	_, err := Compile(document)
	return err
}
