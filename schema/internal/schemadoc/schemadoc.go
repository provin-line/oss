// Package schemadoc is the single JSON Schema policy shared by the
// schema-registry admission check (schema.ValidateJSONSchema) and the in-memory
// validator implementation (schema/local): strict-decode every document the
// library reads, schema or payload (the only JSON decode path permitted on
// protocol boundaries — duplicate keywords, trailing data and invalid Unicode
// are rejected), refuse a number the library would read slowly, pin the
// dialect to Draft 2020-12 (the library's default tracks "latest supported"
// and shifts), and deny external $ref so a schema is self-contained as a
// structural guarantee. A payload reaches the library only through
// Schema.Validate, which decodes it first.
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

	"github.com/santhosh-tekuri/jsonschema/v6"

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

// admissionResourceID is the placeholder compile location used by Validate.
// External $ref is denied and internal ("#/…") refs resolve against the document
// being compiled, so the base URI is immaterial — a fixed value keeps standalone
// validation deterministic.
const admissionResourceID = "urn:dplaax:schema-doc:document"

// Compile strict-decodes document, pins Draft 2020-12, denies external $ref, and
// returns the compiled schema under id. It is the one policy point: callers that
// need the compiled schema (the validator's Add) and callers that only need the
// well-formedness verdict (Validate) share it, so the admission policy cannot
// drift between them.
func Compile(id string, document []byte) (*Schema, error) {
	doc, _, err := decode(document)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	// Content assertion stays off (the library's default): with it, the
	// library would decode a contentMediaType "application/json" string
	// itself, outside decode.
	if err := c.AddResource(id, doc); err != nil {
		return nil, fmt.Errorf("schemadoc: add resource: %w", err)
	}
	compiled, err := c.Compile(id)
	if err != nil {
		return nil, fmt.Errorf("schemadoc: compile: %w", err)
	}
	return &Schema{compiled: compiled, entries: enumEntries(doc)}, nil
}

// Schema is a compiled schema.
type Schema struct {
	compiled *jsonschema.Schema
	entries  int // enum entries and const values in the schema document
}

// The library's work on a payload is not bounded by its size alone: it checks
// a value against enum by comparing it with each entry in turn (a number is
// read as an exact rational again for each comparison), and hashes every
// subtree of an array under uniqueItems at each level of a recursive schema.
// So a payload is refused when it is nested deeper than maxPayloadDepth, or
// when its values times the schema's enum entries and const values exceed
// maxComparisons. The error names the bound.
//
// These bounds cut two shapes of that work; they do not bound the library's
// work for every schema and payload, which needs a budget inside the library.
// They stand in for limits santhosh-tekuri/jsonschema does not have: when it
// can bound its work (or take a context to stop it), Validate uses that and
// these bounds go.
const (
	maxPayloadDepth = 512
	maxComparisons  = 2_000_000
)

// Validate decodes payload as Compile decodes a schema (strictly, within the
// number bounds), refuses one beyond the work bounds above, and validates it
// against the schema.
func (s *Schema) Validate(payload []byte) error {
	inst, shape, err := decode(payload)
	if err != nil {
		return err
	}
	if shape.depth > maxPayloadDepth {
		return fmt.Errorf("schemadoc: payload nested %d deep, beyond the bound of %d levels", shape.depth, maxPayloadDepth)
	}
	if n := uint64(shape.values) * uint64(s.entries); n > maxComparisons {
		return fmt.Errorf("schemadoc: payload of %d values against a schema of %d enum entries and const values: %d comparisons, beyond the bound of %d (values × entries)", shape.values, s.entries, n, maxComparisons)
	}
	if err := s.compiled.Validate(inst); err != nil {
		return fmt.Errorf("schemadoc: does not conform: %s", firstFailure(err))
	}
	return nil
}

// maxFailureBytes bounds the text of a conformance error.
const maxFailureBytes = 1 << 10

// firstFailure states the first place the payload fails to conform, in at
// most maxFailureBytes. The library's own text lists every failure, each with
// its location, which for a large payload runs to hundreds of megabytes.
func firstFailure(err error) string {
	var ve *jsonschema.ValidationError
	text := ""
	if errors.As(err, &ve) {
		for len(ve.Causes) > 0 {
			ve = ve.Causes[0]
		}
		text = ve.Error()
	} else {
		text = err.Error()
	}
	if len(text) > maxFailureBytes {
		text = text[:maxFailureBytes] + "…"
	}
	return text
}

// The library reads every number as an exact rational (math/big), at a cost
// that grows with the number's length and steeply with its exponent: 1e999999
// alone took about 10 ms, so a few kilobytes of such numbers cost seconds, and
// one whose exponent is beyond ±10^6 it cannot read at all (a schema bound
// holding one was dropped, a payload number made validation panic). A number
// it reads is therefore at most maxNumberBytes long, and its exponent part
// (after "e" or "E"), if any, lies within ±maxExponent, beyond binary64's
// range (about 1e±308) with room to spare. Within these bounds a number costs
// it a few microseconds.
const (
	maxNumberBytes = 256
	maxExponent    = 400
)

// shape is what decode measures of a document: its JSON values, and the
// depth of its deepest one (a scalar at the top is depth 1).
type shape struct {
	values int
	depth  int
}

// decode strict-decodes document, refuses a number beyond the bounds the
// library reads in bounded time (maxNumberBytes, maxExponent), and measures
// the document's shape. Compile and Schema.Validate decode every JSON value
// the library reads here.
func decode(document []byte) (any, shape, error) {
	var v any
	if err := canon.NewStrictDecoder(document).Decode(&v); err != nil {
		return nil, shape{}, fmt.Errorf("schemadoc: not strict-decodable JSON: %w", err)
	}
	var sh shape
	if err := walk(v, 1, &sh); err != nil {
		return nil, shape{}, err
	}
	return v, sh, nil
}

func walk(v any, depth int, sh *shape) error {
	sh.values++
	sh.depth = max(sh.depth, depth)
	switch t := v.(type) {
	case map[string]any:
		for _, e := range t {
			if err := walk(e, depth+1, sh); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := walk(e, depth+1, sh); err != nil {
				return err
			}
		}
	case json.Number:
		return checkNumber(string(t))
	}
	return nil
}

// enumEntries counts the entries of every "enum" array and every "const" in
// a schema document. A property named "const" counts too, which only
// overstates the work.
func enumEntries(v any) int {
	n := 0
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			switch k {
			case "enum":
				if list, ok := e.([]any); ok {
					n += len(list)
				}
			case "const":
				n++
			}
			n += enumEntries(e)
		}
	case []any:
		for _, e := range t {
			n += enumEntries(e)
		}
	}
	return n
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
	_, err := Compile(admissionResourceID, document)
	return err
}
