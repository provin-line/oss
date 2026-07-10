package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/vc"
)

// schemaGetter is the narrow read seam the schema wiring needs from the schema
// registry — *schemaregistry.Service satisfies it. Kept consumer-defined so the
// bridge and boot-resolve depend on Get alone, not the whole service.
type schemaGetter interface {
	Get(ctx context.Context, name, version string) (*store.Schema, error)
}

// schemaResolver bridges the local schema registry to vc.SchemaResolver on the
// verify path: it parses a canonical schema URI back to its (name, version) and
// serves the registered body + format. Same-process — no network hop. The
// verifier recomputes the content hash over the body itself, so this bridge is
// trusted only for retrieval, never for integrity.
type schemaResolver struct {
	svc schemaGetter
}

func (r schemaResolver) ResolveSchema(ctx context.Context, ref vc.SchemaRef) (*vc.ResolvedSchema, error) {
	name, version, err := vc.ParseSchemaURI(ref.ID)
	if err != nil {
		return nil, err // ErrSchemaInvalidRef — a deterministic malformed reference (failed)
	}
	sc, err := r.svc.Get(ctx, name, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s@%s", vc.ErrSchemaNotFound, name, version)
		}
		return nil, err // transient (ctx, I/O) — verifier maps to indeterminate
	}
	return &vc.ResolvedSchema{Format: sc.SchemaFormat, Body: sc.SchemaBody}, nil
}

// resolveSchemaRefAtBoot resolves a config schema-ref short-form
// ("<name>@<version>") to the full, signed reference a producing loop embeds in
// every credential it issues. Fail-closed: a missing or deprecated schema is a
// boot error (an operator must register or advance to a current version before
// the loop runs). The content hash is computed here, once, over the registered
// body — issuance itself does no registry I/O (schemas are immutable), and a
// schema deprecated after boot keeps issuing until the next restart.
func resolveSchemaRefAtBoot(ctx context.Context, svc schemaGetter, shortForm string) (vc.SchemaRef, error) {
	name, version, err := vc.SplitSchemaRef(shortForm)
	if err != nil {
		return vc.SchemaRef{}, err
	}
	sc, err := svc.Get(ctx, name, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return vc.SchemaRef{}, fmt.Errorf("schema %s@%s is not registered", name, version)
		}
		return vc.SchemaRef{}, fmt.Errorf("resolve schema %s@%s: %w", name, version, err)
	}
	if sc.Deprecated {
		return vc.SchemaRef{}, fmt.Errorf("schema %s@%s is deprecated: register and reference a current version", name, version)
	}
	sum := sha256.Sum256(sc.SchemaBody)
	return vc.SchemaRef{
		ID:          vc.SchemaURI(name, version),
		Type:        sc.SchemaFormat,
		ContentHash: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}
