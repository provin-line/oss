package netcompose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/vc"
)

// fakeSchemaGetter is a SchemaGetter backed by an in-memory map keyed by
// "name@version"; a missing key returns store.ErrNotFound.
type fakeSchemaGetter struct {
	schemas map[string]*store.Schema
}

func (f fakeSchemaGetter) Get(_ context.Context, name, version string) (*store.Schema, error) {
	if s, ok := f.schemas[name+"@"+version]; ok {
		return s, nil
	}
	return nil, store.ErrNotFound
}

func hashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestResolveSchemaRefAtBoot(t *testing.T) {
	body := []byte(`{"type":"object"}`)
	getter := fakeSchemaGetter{schemas: map[string]*store.Schema{
		"orders@2026-07-10-abcdef0123456789": {Name: "orders", Version: "2026-07-10-abcdef0123456789", SchemaFormat: "JsonSchema", SchemaBody: body},
		"legacy@2026-01-01-deadbeefdeadbeef": {Name: "legacy", Version: "2026-01-01-deadbeefdeadbeef", SchemaFormat: "JsonSchema", SchemaBody: body, Deprecated: true},
	}}

	// Registered, current: full signed reference with canonical URI + content hash.
	ref, err := ResolveSchemaRefAtBoot(context.Background(), getter, "orders@2026-07-10-abcdef0123456789")
	if err != nil {
		t.Fatalf("ResolveSchemaRefAtBoot: %v", err)
	}
	want := vc.SchemaRef{ID: "dplaax:schema/orders@2026-07-10-abcdef0123456789", Type: "JsonSchema", ContentHash: hashOf(body)}
	if ref != want {
		t.Errorf("ref = %+v, want %+v", ref, want)
	}

	// Not registered: boot error (fail-closed).
	if _, err := ResolveSchemaRefAtBoot(context.Background(), getter, "missing@2026-07-10-abcdef0123456789"); err == nil {
		t.Error("unregistered schema-ref: want boot error, got nil")
	}

	// Deprecated: boot error (must advance to a current version).
	if _, err := ResolveSchemaRefAtBoot(context.Background(), getter, "legacy@2026-01-01-deadbeefdeadbeef"); err == nil {
		t.Error("deprecated schema-ref: want boot error, got nil")
	}

	// Malformed short-form: boot error.
	if _, err := ResolveSchemaRefAtBoot(context.Background(), getter, "noversion"); err == nil {
		t.Error("malformed schema-ref: want boot error, got nil")
	}
}

func TestSchemaResolver_ResolveSchema(t *testing.T) {
	body := []byte(`{"type":"object"}`)
	getter := fakeSchemaGetter{schemas: map[string]*store.Schema{
		"orders@2026-07-10-abcdef0123456789": {SchemaFormat: "JsonSchema", SchemaBody: body},
	}}
	r := SchemaBridge{Svc: getter}

	// Valid canonical URI resolves to body + format.
	got, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: "dplaax:schema/orders@2026-07-10-abcdef0123456789"})
	if err != nil {
		t.Fatalf("ResolveSchema: %v", err)
	}
	if got.Format != "JsonSchema" || string(got.Body) != string(body) {
		t.Errorf("resolved = %+v, want JsonSchema + body", got)
	}

	// Malformed IDs -> ErrSchemaInvalidRef (deterministic, mapped to failed). This
	// includes path-traversal segments (".","..") the registry would reject as an
	// invalid argument — the grammar rejects them before any registry call, so a
	// structurally-invalid reference never lands in the transient/indeterminate bucket.
	for _, bad := range []string{"not-a-schema-uri", "dplaax:schema/.@2026-07-10-abcdef0123456789", "dplaax:schema/..@2026-07-10-abcdef0123456789"} {
		if _, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: bad}); !errors.Is(err, vc.ErrSchemaInvalidRef) {
			t.Errorf("ResolveSchema(%q) err = %v, want ErrSchemaInvalidRef", bad, err)
		}
	}

	// Well-formed but unregistered -> ErrSchemaNotFound (definitive).
	if _, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: "dplaax:schema/gone@2026-07-10-abcdef0123456789"}); !errors.Is(err, vc.ErrSchemaNotFound) {
		t.Errorf("missing schema err = %v, want ErrSchemaNotFound", err)
	}
}
