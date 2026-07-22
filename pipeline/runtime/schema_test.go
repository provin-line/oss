package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/provin-line/oss/vc"
)

// fakeSchemaGetter is a SchemaGetter backed by an in-memory map keyed by
// "name@version"; a missing key returns ErrSchemaNotFound. (Relocated from
// internal/netcompose's schemaresolver_test.go when boot-time schema-ref
// resolution moved here — the netcompose copy of the resolver is gone.)
type fakeSchemaGetter struct {
	schemas map[string]*Schema
}

func (f fakeSchemaGetter) Get(_ context.Context, name, version string) (*Schema, error) {
	if s, ok := f.schemas[name+"@"+version]; ok {
		return s, nil
	}
	return nil, ErrSchemaNotFound
}

func schemaHashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestResolveSchemaRefAtBoot(t *testing.T) {
	body := []byte(`{"type":"object"}`)
	getter := fakeSchemaGetter{schemas: map[string]*Schema{
		"orders@2026-07-10-abcdef0123456789": {Format: "JsonSchema", Body: body},
		"legacy@2026-01-01-deadbeefdeadbeef": {Format: "JsonSchema", Body: body, Deprecated: true},
	}}

	// Registered, current: full signed reference with canonical URI + content hash.
	ref, err := resolveSchemaRefAtBoot(context.Background(), getter, "orders@2026-07-10-abcdef0123456789")
	if err != nil {
		t.Fatalf("resolveSchemaRefAtBoot: %v", err)
	}
	want := vc.SchemaRef{ID: "dplaax:schema/orders@2026-07-10-abcdef0123456789", Type: "JsonSchema", ContentHash: schemaHashOf(body)}
	if ref != want {
		t.Errorf("ref = %+v, want %+v", ref, want)
	}

	// Not registered: boot error (fail-closed).
	if _, err := resolveSchemaRefAtBoot(context.Background(), getter, "missing@2026-07-10-abcdef0123456789"); err == nil {
		t.Error("unregistered schema-ref: want boot error, got nil")
	}

	// Deprecated: boot error (must advance to a current version).
	if _, err := resolveSchemaRefAtBoot(context.Background(), getter, "legacy@2026-01-01-deadbeefdeadbeef"); err == nil {
		t.Error("deprecated schema-ref: want boot error, got nil")
	}

	// Malformed short-form: boot error.
	if _, err := resolveSchemaRefAtBoot(context.Background(), getter, "noversion"); err == nil {
		t.Error("malformed schema-ref: want boot error, got nil")
	}
}
