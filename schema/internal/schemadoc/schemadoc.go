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
// with patches: a work budget, an error for a number it cannot read where
// upstream panics, and compiling a schema in time linear in its size, its
// metaschema check within a budget (its README.md).
//
// Internal: this is an implementation detail, not part of the public API. The
// public entry points are schema.ValidateJSONSchema (admission) and the
// schema.Validator implementations.
package schemadoc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	return nil, fmt.Errorf("schemadoc: external $ref is not allowed: %q", url)
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
	return compileWithin(document, schemaBudgetBase+schemaBudgetPerByte*int64(len(document)))
}

// compileWithin is Compile, checking the schema against its metaschema
// within budget steps.
func compileWithin(document []byte, budget int64) (*Schema, error) {
	doc, sh, err := decode(document)
	if err != nil {
		return nil, err
	}
	if sh.depth > maxSchemaDepth {
		return nil, fmt.Errorf("schemadoc: schema nested %d deep, beyond the bound of %d levels", sh.depth, maxSchemaDepth)
	}
	if bound := schemaObjectBase + int64(len(document))/schemaBytesPerObject; sh.objects > bound {
		return nil, fmt.Errorf("schemadoc: the schema holds %d objects and booleans, beyond the bound of %d (%d, and one per %d bytes of the schema)", sh.objects, bound, schemaObjectBase, schemaBytesPerObject)
	}
	if bound := schemaPointerBase + schemaPointerBytesPerByte*int64(len(document)); sh.pointers > bound {
		return nil, fmt.Errorf("schemadoc: the schema's JSON pointers and URLs (its values' pointers, and what its $id and $ref resolve to) come to %d bytes, beyond the bound of %d (%d, and %d per byte of the schema)", sh.pointers, bound, schemaPointerBase, schemaPointerBytesPerByte)
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
	compiled, err := c.CompileWithBudget(resourceID, budget)
	patterns.compiled = true
	var exceeded *jsonschema.BudgetExceededError
	switch {
	case errors.As(err, &exceeded) && exceeded.Nested:
		return nil, fmt.Errorf("schemadoc: checking the schema against its metaschema nests schemas deeper than %d", jsonschema.MaxNesting)
	case errors.As(err, &exceeded):
		return nil, fmt.Errorf("schemadoc: checking the schema against its metaschema needs more than its work budget of %d steps (%d, and %d per byte of the schema)", exceeded.Budget, schemaBudgetBase, schemaBudgetPerByte)
	case err != nil:
		return nil, compileError(err)
	}
	return &Schema{compiled: compiled}, nil
}

// Compile checks a schema against its metaschema within a work budget of
// schemaBudgetBase steps and schemaBudgetPerByte per byte of the schema
// (jsonschema.CompileWithBudget), so a form of schema whose check takes more
// than linear work, found or not, is refused at that bound rather than run.
// SchemaStore's 882 schemas that compile here need at most 4.8 steps per
// byte, and at most 11.5% of their budget (measured).
const (
	schemaBudgetBase    = 1 << 20
	schemaBudgetPerByte = 16
)

// What the library does and keeps in compiling a schema grows with the
// schema's shape, not only its size, and a schema a validator registers is
// kept compiled. So Compile refuses a schema:
//
//   - nested deeper than maxSchemaDepth: the work per subschema grows with
//     its depth (the library rebuilds and hashes its location at each level);
//   - holding more than schemaObjectBase objects and booleans and one per
//     schemaBytesPerObject bytes of the schema: the library keeps a
//     subschema of about 1 KB for each it compiles (970 bytes for an empty
//     one), and a subschema is an object or a boolean (numbers, strings and
//     arrays, such as an enum's entries, are not counted). They are counted
//     wherever they are, in a default or an example too: a $ref can make
//     any of them a subschema;
//   - whose JSON pointers and URLs, summed, pass schemaPointerBase bytes and
//     schemaPointerBytesPerByte per byte of the schema: the library keeps
//     each subschema's pointer, and its location with the pointer escaped
//     for a URL, so the pointers are counted escaped so (tokenBytes); it
//     keeps the URL each id resolves to ($id, or draft-04's id), and builds
//     the one each reference resolves to ($ref, $dynamicRef,
//     $recursiveRef), each counted escaped, at its base's length and its
//     own (resolvedBytes); and it finds each object's resource by its base
//     URL, which is counted once for each object.
//
// SchemaStore's 1,027 schemas nest at most 23 deep, hold at most one object
// or boolean per 40 bytes, and their pointers and URLs come to at most 4.03
// bytes per byte; the 882 that compile here keep at most 31 bytes per byte of
// the schema (measured). Within the bounds a schema of 1 MiB keeps at most
// about 170 MB once compiled (about 1 KB per object or boolean, and its
// pointers and locations, each within the bound on pointers). The worst
// shapes measured keep 127 MB and compile in at most about 0.5 s; one the
// metaschema's budget refuses is refused in at most about 0.8 s. The library
// reads an array index only as RFC 6901 writes one, so an item has one
// location, and resolves each URL a reference resolves to once, so a
// reference to a long location is not built again for each reference.
const (
	maxSchemaDepth            = 64
	schemaObjectBase          = 4096
	schemaBytesPerObject      = 8
	schemaPointerBase         = 1 << 16
	schemaPointerBytesPerByte = 16
)

// compileError states why a schema did not compile within maxFailureBytes.
// For a schema the metaschema refuses it states the first failure
// (firstFailure): the library's own text lists every failure, indented per
// level, and is not built.
func compileError(err error) error {
	var invalid *jsonschema.SchemaValidationError
	if errors.As(err, &invalid) {
		return errors.New(cutFailure("schemadoc: compile: the schema does not conform to its metaschema: " + firstFailure(invalid.Err)))
	}
	return errors.New(cutFailure("schemadoc: compile: " + err.Error()))
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
// once), so Go parses it in at most about 240 ns per byte (measured, below;
// alternations sharing prefixes grow a little faster than linearly, up to
// about 72 ns per byte, Go's parser refusing one past about 256 KB);
// compiled only within a size n of maxPatternSize (8,192, an upper bound of
// its instructions; compileRegexpWithin); and charged by its length and n.
// Matching one position of a string (each byte, and the end) against it
// costs n/16 steps besides the byte's own (16 being
// jsonschema.PatternInstructionsPerStep).
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
	inst, sh, err := decode(payload)
	if err != nil {
		return err
	}
	if sh.depth > maxPayloadDepth {
		return fmt.Errorf("schemadoc: payload nested %d deep, beyond the bound of %d levels", sh.depth, maxPayloadDepth)
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
		return errors.New(cutFailure("schemadoc: does not conform: " + firstFailure(err)))
	}
	return nil
}

// maxFailureBytes bounds the text of a conformance or compile error this
// package states, the whole of it; maxLocationBytes, the location of a
// failure firstFailure states, so the keyword it fails fits after a long one.
const (
	maxFailureBytes  = 1 << 10
	maxLocationBytes = maxFailureBytes / 2
)

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
	var loc strings.Builder
	for _, tok := range ve.InstanceLocation {
		writeWithin(&loc, "/")
		writeEscaped(&loc, pointerEscaper.Replace(tok), true)
	}
	var b strings.Builder
	b.WriteString("at '")
	b.WriteString(cut(loc.String(), maxLocationBytes))
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

// cutFailure cuts text to maxFailureBytes (cut).
func cutFailure(text string) string { return cut(text, maxFailureBytes) }

// cut cuts text to at most bound bytes, where a character starts, and marks
// the cut with "…", within the bound.
func cut(text string, bound int) string {
	if len(text) <= bound {
		return text
	}
	n := bound - len("…")
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

// pathBytes is, for each byte, how many bytes url.PathEscape writes for it:
// the library keeps each subschema's location escaped so, its pointer's
// tokens escaped first as RFC 6901 says (~ and / as two bytes).
var pathBytes = func() (n [256]int64) {
	for c := range n {
		n[c] = int64(len(url.PathEscape(string([]byte{byte(c)}))))
	}
	n['~'], n['/'] = 2, 2
	return n
}()

// tokenBytes is how many bytes the pointer token of the name k takes, as the
// library keeps it in a subschema's location.
func tokenBytes(k string) int64 {
	var n int64
	for i := 0; i < len(k); i++ {
		n += pathBytes[k[i]]
	}
	return n
}

// resolvedBytes is at most how long the URL ref resolves to against a base
// of base bytes is, as the library writes it, each byte escaped
// (pathBytes): ref itself when it names a scheme, else the base and ref.
func resolvedBytes(base int64, ref string) int64 {
	var n int64
	for i := 0; i < len(ref); i++ {
		n += pathBytes[ref[i]]
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c == ':' && i > 0:
			return n
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
			continue
		}
		break
	}
	return base + n
}

// digits is how many decimal digits i, at least 0, has.
func digits(i int) int64 {
	n := int64(1)
	for ; i >= 10; i /= 10 {
		n++
	}
	return n
}

// shape is what decode measures of a document: the depth of its deepest
// value (each object, array and scalar is a level; a scalar at the top is
// depth 1), its objects and booleans, and the length of the JSON pointer
// (RFC 6901) of each of its values, its tokens escaped for a URL's path as
// the library keeps them (tokenBytes), and of each URL its ids and
// references resolve to (resolvedBytes), summed.
type shape struct {
	depth    int
	objects  int64
	pointers int64
}

// decode strict-decodes document, refuses a number beyond the bounds the
// library reads in bounded time (maxNumberBytes, maxExponent), and measures
// its shape. Compile and Schema.Validate decode every JSON value the library
// reads here.
func decode(document []byte) (any, shape, error) {
	var v any
	if err := canon.NewStrictDecoder(document).Decode(&v); err != nil {
		return nil, shape{}, fmt.Errorf("schemadoc: not strict-decodable JSON: %w", err)
	}
	var sh shape
	if err := walk(v, 1, 0, int64(len(resourceID)), &sh); err != nil {
		return nil, shape{}, err
	}
	return v, sh, nil
}

// walk checks every number in v, whose depth is at, whose JSON pointer is
// pointer bytes long and whose base URL is base bytes long, and adds v and
// its members to sh.
func walk(v any, at int, pointer, base int64, sh *shape) error {
	sh.depth = max(sh.depth, at)
	sh.pointers += pointer
	switch t := v.(type) {
	case bool:
		sh.objects++
	case map[string]any:
		sh.objects++
		// The URL an id resolves to is a new base; draft-04 writes it id. A
		// draft before 2019-09 ignores an $id beside a $ref, which then
		// resolves against the base outside it, so each reference, and what
		// is below, is counted at the longer of the two.
		outer := base
		for _, kw := range []string{"$id", "id"} {
			if id, ok := t[kw].(string); ok {
				resolved := resolvedBytes(outer, id)
				sh.pointers += resolved
				base = max(base, resolved)
			}
		}
		for _, kw := range []string{"$ref", "$dynamicRef", "$recursiveRef"} {
			if ref, ok := t[kw].(string); ok {
				sh.pointers += resolvedBytes(base, ref)
			}
		}
		// The library finds the object's resource by its base URL, hashing
		// it whole.
		sh.pointers += base
		for k, e := range t {
			if err := walk(e, at+1, pointer+1+tokenBytes(k), base, sh); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range t {
			if err := walk(e, at+1, pointer+1+digits(i), base, sh); err != nil {
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
