// Package schemadoc is the single JSON Schema document policy shared by the
// schema-registry admission check (schema.ValidateJSONSchema) and the in-memory
// validator implementation (schema/local): strict-decode the document (the only
// JSON decode path permitted on protocol boundaries — duplicate keywords,
// trailing data and invalid Unicode are rejected), pin the dialect to Draft
// 2020-12 (the library's default tracks "latest supported" and shifts), and
// deny external $ref so a schema is self-contained as a structural guarantee.
//
// Internal: this is an implementation detail, not part of the public API. The
// public entry points are schema.ValidateJSONSchema (admission) and the
// schema.Validator implementations.
package schemadoc

import (
	"fmt"

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
func Compile(id string, document []byte) (*jsonschema.Schema, error) {
	var doc any
	if err := canon.NewStrictDecoder(document).Decode(&doc); err != nil {
		return nil, fmt.Errorf("schemadoc: not strict-decodable JSON: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	if err := c.AddResource(id, doc); err != nil {
		return nil, fmt.Errorf("schemadoc: add resource: %w", err)
	}
	compiled, err := c.Compile(id)
	if err != nil {
		return nil, fmt.Errorf("schemadoc: compile: %w", err)
	}
	return compiled, nil
}

// Validate reports whether document is a well-formed, self-contained JSON Schema:
// it must strict-decode, compile under Draft 2020-12, and reference no external
// $ref. It registers nothing and resolves no reference.
func Validate(document []byte) error {
	_, err := Compile(admissionResourceID, document)
	return err
}
