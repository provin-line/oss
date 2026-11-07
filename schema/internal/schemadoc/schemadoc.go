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
	doc, err := decode(document)
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
	return &Schema{compiled: compiled}, nil
}

// Schema is a compiled schema.
type Schema struct {
	compiled *jsonschema.Schema
}

// Validate decodes payload as Compile decodes a schema (strictly, within the
// number bounds) and validates it against the schema.
func (s *Schema) Validate(payload []byte) error {
	inst, err := decode(payload)
	if err != nil {
		return err
	}
	if err := s.compiled.Validate(inst); err != nil {
		return fmt.Errorf("schemadoc: does not conform: %w", err)
	}
	return nil
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

// decode strict-decodes document and refuses a number beyond the bounds the
// library reads in bounded time (maxNumberBytes, maxExponent). Compile and
// Schema.Validate decode every JSON value the library reads here.
func decode(document []byte) (any, error) {
	var v any
	if err := canon.NewStrictDecoder(document).Decode(&v); err != nil {
		return nil, fmt.Errorf("schemadoc: not strict-decodable JSON: %w", err)
	}
	if err := checkNumbers(v); err != nil {
		return nil, err
	}
	return v, nil
}

func checkNumbers(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for _, e := range t {
			if err := checkNumbers(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := checkNumbers(e); err != nil {
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
	_, err := Compile(admissionResourceID, document)
	return err
}
