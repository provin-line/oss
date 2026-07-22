package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// Schema carries only the fields resolveSchemaRefAtBoot reads out of a
// registered schema entry — mirrored from
// network/pkg/services/schemaregistry/store.Schema's SchemaFormat, SchemaBody,
// and Deprecated fields (Name/Version/Prerelease are addressing, not content,
// and are never read here). A runtime-owned type so this package stays
// network-agnostic (network/ and pipeline/ never import each other, AGENTS.md
// rule 2); cmd/standalone's SchemaGetter adapter converts the real registry
// service's *store.Schema into this shape.
type Schema struct {
	Format     string
	Body       []byte
	Deprecated bool
}

// SchemaGetter is the narrow read seam a producing loop's boot-time
// schema-ref resolution needs. Mirrors internal/netcompose's own SchemaGetter
// interface shape (method name/params), but returns the runtime-owned Schema
// above instead of the network-side store.Schema — internal/netcompose keeps
// its own SchemaGetter for the network-side SchemaBridge (the verify-path
// bridge to vc.SchemaResolver); two layers, two owners, cmd/standalone
// adapts the one real schema-registry service to both.
type SchemaGetter interface {
	Get(ctx context.Context, name, version string) (*Schema, error)
}

// ErrSchemaNotFound is the sentinel a SchemaGetter implementation returns
// (directly, or wrapped so errors.Is still matches) when the requested
// (name, version) pair is not registered. resolveSchemaRefAtBoot maps it to a
// legible "not registered" boot error, distinct from a transient/backend
// failure. cmd/standalone's adapter maps the real registry's
// store.ErrNotFound to this sentinel.
var ErrSchemaNotFound = errors.New("runtime: schema not registered")

// resolveSchemaRefAtBoot resolves a config schema-ref short-form
// ("<name>@<version>") to the full, signed reference a producing loop embeds
// in every credential it issues. Fail-closed: a missing or deprecated schema
// is a boot error (an operator must register or advance to a current version
// before the loop runs). The content hash is computed here, once, over the
// registered body — issuance itself does no registry I/O (schemas are
// immutable), and a schema deprecated after boot keeps issuing until the next
// restart.
//
// Mirrors internal/netcompose/schemaresolver.go's ResolveSchemaRefAtBoot
// (severed here — see SchemaGetter's doc — so pipeline/runtime no longer
// imports internal/netcompose).
func resolveSchemaRefAtBoot(ctx context.Context, svc SchemaGetter, shortForm string) (vc.SchemaRef, error) {
	name, version, err := vc.SplitSchemaRef(shortForm)
	if err != nil {
		return vc.SchemaRef{}, err
	}
	sc, err := svc.Get(ctx, name, version)
	if err != nil {
		if errors.Is(err, ErrSchemaNotFound) {
			return vc.SchemaRef{}, fmt.Errorf("schema %s@%s is not registered", name, version)
		}
		return vc.SchemaRef{}, fmt.Errorf("resolve schema %s@%s: %w", name, version, err)
	}
	if sc.Deprecated {
		return vc.SchemaRef{}, fmt.Errorf("schema %s@%s is deprecated: register and reference a current version", name, version)
	}
	sum := sha256.Sum256(sc.Body)
	return vc.SchemaRef{
		ID:          vc.SchemaURI(name, version),
		Type:        sc.Format,
		ContentHash: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}
