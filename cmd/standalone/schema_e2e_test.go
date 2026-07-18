package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/internal/netcompose"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// TestSchemaValidation_RegistryToVerification exercises the whole schema wiring
// against a REAL registry (not a fake resolver): register a schema, boot-resolve
// its config short-form into the signed reference the issuance path embeds, then
// verify credentials carrying that reference through the same registry via the
// SchemaBridge bridge. The key property is cross-side agreement — the content
// hash resolveSchemaRefAtBoot computes at issuance equals the one the verifier
// re-derives at verification (independent code paths over the same registry).
func TestSchemaValidation_RegistryToVerification(t *testing.T) {
	ctx := context.Background()
	svc := schemaregistry.New(schemayaml.New(t.TempDir()))
	body := []byte(`{"type":"object","properties":{"reading":{"type":"number"}}}`)
	sc, err := svc.Register(ctx, "readings", "JsonSchema", body, "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Issuance side: boot-resolve the config short-form to the signed reference.
	ref, err := resolveSchemaRefAtBoot(ctx, svc, "readings@"+sc.Version)
	if err != nil {
		t.Fatalf("resolveSchemaRefAtBoot: %v", err)
	}

	// Verification side: a verifier wired to the same registry through the bridge.
	verifier := vc.NewVerifier(local.New(), ed25519.Verifier{}, vc.WithSchemaResolver(netcompose.SchemaBridge{Svc: svc}))

	build := func(r vc.SchemaRef) *vc.PipelinePassCredential {
		cred, err := vc.New(vc.CredentialFields{
			Issuer:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p:process:src",
			ValidFrom: time.Now(),
			Subject: vc.CredentialSubjectFields{
				PipelineID:          "p",
				ProcessID:           "src",
				TransformationClaim: vc.ClaimConvert,
				OutputHash:          "sha256:" + strings.Repeat("a", 64),
				Schema:              r,
			},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return cred
	}
	dataIntegrity := func(cred *vc.PipelinePassCredential) vc.ConfidenceState {
		res, err := verifier.Verify(ctx, cred)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		return res.Axes.DataIntegrity
	}

	// The issued reference round-trips through the registry: DataIntegrity verified.
	if got := dataIntegrity(build(ref)); got != vc.ConfidenceVerified {
		t.Errorf("issued schema-ref: DataIntegrity=%v, want Verified", got)
	}

	// A tampered content hash no longer matches the registered body: failed.
	tampered := ref
	tampered.ContentHash = "sha256:" + strings.Repeat("b", 64)
	if got := dataIntegrity(build(tampered)); got != vc.ConfidenceFailed {
		t.Errorf("tampered contentHash: DataIntegrity=%v, want Failed", got)
	}

	// A reference to an unregistered version is a definitive miss: failed.
	gone := vc.SchemaRef{ID: vc.SchemaURI("readings", "2099-01-01-ffffffffffffffff"), Type: "JsonSchema", ContentHash: ref.ContentHash}
	if got := dataIntegrity(build(gone)); got != vc.ConfidenceFailed {
		t.Errorf("unregistered schema: DataIntegrity=%v, want Failed", got)
	}

	// A declared Type that misdescribes the registered format: failed (spoof guard).
	spoofed := ref
	spoofed.Type = "OpenAPI"
	if got := dataIntegrity(build(spoofed)); got != vc.ConfidenceFailed {
		t.Errorf("type-spoofed schema-ref: DataIntegrity=%v, want Failed", got)
	}

	// Deprecation is a NEW-use bar, not a history invalidator: a credential issued
	// against a schema that is later deprecated MUST still verify (the bridge
	// resolves deprecated bodies unconditionally — the boot-side fail-closed check
	// lives in issuance, not verification).
	if err := svc.Deprecate(ctx, "readings", sc.Version); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if got := dataIntegrity(build(ref)); got != vc.ConfidenceVerified {
		t.Errorf("deprecated schema on verify: DataIntegrity=%v, want Verified (history stays verifiable)", got)
	}
}
