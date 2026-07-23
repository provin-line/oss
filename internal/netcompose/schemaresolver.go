package netcompose

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/vc"
)

// SchemaGetter is the narrow read seam the schema wiring needs from the schema
// registry — *schemaregistry.Service satisfies it. Kept consumer-defined so the
// bridge depends on Get alone, not the whole service. Exported because
// SchemaBridge.Svc is of this type and the composition root constructs the
// bridge directly (netcompose.SchemaBridge{Svc: schemaSvc} in cmd/network's
// main). The data plane's boot-time schema-ref
// resolution has its OWN getter seam (pipeline/runtime.SchemaGetter, over a
// runtime-owned Schema type) — two layers, two owners, never an import
// between them (AGENTS.md rule 2).
type SchemaGetter interface {
	Get(ctx context.Context, name, version string) (*store.Schema, error)
}

// SchemaBridge bridges the local schema registry to vc.SchemaResolver on the
// verify path: it parses a canonical schema URI back to its (name, version) and
// serves the registered body + format. Same-process — no network hop. The
// verifier recomputes the content hash over the body itself, so this bridge is
// trusted only for retrieval, never for integrity. Named SchemaBridge (not
// SchemaResolver) to avoid a name clash with vc.SchemaResolver, the interface
// it implements; Svc is exported so the composition root (cmd/network's
// main) can construct it directly (netcompose.SchemaBridge{Svc: schemaSvc}).
type SchemaBridge struct {
	Svc SchemaGetter
}

func (r SchemaBridge) ResolveSchema(ctx context.Context, ref vc.SchemaRef) (*vc.ResolvedSchema, error) {
	name, version, err := vc.ParseSchemaURI(ref.ID)
	if err != nil {
		return nil, err // ErrSchemaInvalidRef — a deterministic malformed reference (failed)
	}
	sc, err := r.Svc.Get(ctx, name, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s@%s", vc.ErrSchemaNotFound, name, version)
		}
		return nil, err // transient (ctx, I/O) — verifier maps to indeterminate
	}
	return &vc.ResolvedSchema{Format: sc.SchemaFormat, Body: sc.SchemaBody}, nil
}

// Boot-time schema-ref resolution (the issuance side) lives in
// pipeline/runtime (resolveSchemaRefAtBoot there): only the data plane embeds
// a schema-ref at issuance, and this control-plane composition never does —
// the netcompose copy that predated the pipeline/runtime extraction is gone.
// This file keeps only the VERIFY-side bridge above.
