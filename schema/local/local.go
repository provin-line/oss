// Package local is the in-memory schema.Validator for the PoC and in-org
// deployments: a SchemaRef.ID → registered JSON Schema map, the validation
// counterpart of resolver/local. A registry-backed client lands with the
// network layer.
//
// Validate enforces two things in order: the content commitment — the
// registered schema's SHA-256 must equal the SchemaRef.ContentHash, so a
// retroactively-modified schema is detected (the data-integrity axis's
// schema-reference check) — and then structural conformance of the payload
// against the schema (santhosh-tekuri/jsonschema).
//
// Both the schema document and the payload are decoded through
// canon.StrictDecoder — the one JSON decode path permitted on protocol
// boundaries — so duplicate keys, trailing data, and invalid Unicode are
// rejected here exactly as elsewhere in the stack; the validator never approves
// ambiguous bytes the codec would refuse. The compiler denies external $ref
// (denyLoader) so schemas are self-contained as a structural guarantee, and
// pins the default dialect to Draft 2020-12, under which "format" is an
// annotation, not an assertion. A schema that explicitly declares an older
// $schema (e.g. draft-07) resolves its embedded meta-schema and follows that
// dialect's rules — including format assertion — by design.
package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/vc"
)

// schemaType is the only SchemaRef.Type this validator understands.
const schemaType = "JsonSchema"

// denyLoader makes "self-contained schema" a STRUCTURAL guarantee rather than a
// convention: any external $ref (file://, http(s)://, …) fails closed at
// compile time. Without it the library's default FileLoader would read local
// files referenced by a crafted $ref — a local-file-inclusion vector in a layer
// whose threat model already assumes adversarially modified schemas. Internal
// ("#/…") refs and refs to the resource being compiled do not hit the loader.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schema/local: external $ref is not allowed: %s", url)
}

// Validator is an in-memory JSON Schema validator. Safe for concurrent use.
type Validator struct {
	mu      sync.RWMutex
	schemas map[string]*entry
}

type entry struct {
	hash     string // "sha256:<hex>" of the registered schema document
	compiled *jsonschema.Schema
}

// New returns an empty Validator.
func New() *Validator {
	return &Validator{schemas: map[string]*entry{}}
}

// Add registers a JSON Schema document under id, compiling it so a malformed
// schema fails loudly here rather than at first validation. Re-adding an id
// overwrites it.
func (v *Validator) Add(id string, document []byte) error {
	// Strict-decode the schema document (the only JSON decode path on protocol
	// boundaries): duplicate keywords / trailing data / invalid Unicode are
	// rejected, so the registry never commits-by-hash to a schema whose
	// validation semantics are ambiguous across implementations.
	var doc any
	if err := canon.NewStrictDecoder(document).Decode(&doc); err != nil {
		return fmt.Errorf("schema/local: schema %q is not strict-decodable JSON: %w", id, err)
	}
	c := jsonschema.NewCompiler()
	// Pin the draft so a no-$schema document validates the same way across
	// library versions (the library's default tracks "latest supported" and
	// shifts), and deny external $ref resolution.
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	if err := c.AddResource(id, doc); err != nil {
		return fmt.Errorf("schema/local: add schema %q: %w", id, err)
	}
	compiled, err := c.Compile(id)
	if err != nil {
		return fmt.Errorf("schema/local: compile schema %q: %w", id, err)
	}
	sum := sha256.Sum256(document)
	v.mu.Lock()
	v.schemas[id] = &entry{
		hash:     "sha256:" + hex.EncodeToString(sum[:]),
		compiled: compiled,
	}
	v.mu.Unlock()
	return nil
}

// Validate resolves the schema named by ref.ID, verifies the registered
// schema's content hash matches ref.ContentHash, and validates payload against
// it. A content-hash mismatch and a structural violation are both errors; the
// error names the failure.
func (v *Validator) Validate(_ context.Context, payload []byte, ref vc.SchemaRef) error {
	if ref.Type != schemaType {
		return fmt.Errorf("schema/local: unsupported schema type %q (want %q)", ref.Type, schemaType)
	}
	v.mu.RLock()
	e, ok := v.schemas[ref.ID]
	v.mu.RUnlock()
	if !ok {
		return fmt.Errorf("schema/local: no schema registered for %q", ref.ID)
	}
	if e.hash != ref.ContentHash {
		return fmt.Errorf("schema/local: schema %q content hash %s != reference %s (schema-reference mismatch)", ref.ID, e.hash, ref.ContentHash)
	}
	// Strict-decode the payload too, so schema validation cannot approve
	// duplicate-key / trailing-data JSON that the rest of the stack's strict
	// decoder would reject (consistent wire semantics across the pipeline).
	var inst any
	if err := canon.NewStrictDecoder(payload).Decode(&inst); err != nil {
		return fmt.Errorf("schema/local: payload is not strict-decodable JSON: %w", err)
	}
	if err := e.compiled.Validate(inst); err != nil {
		return fmt.Errorf("schema/local: payload does not conform to %q: %w", ref.ID, err)
	}
	return nil
}
