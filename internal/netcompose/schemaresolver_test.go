package netcompose

import (
	"context"
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
