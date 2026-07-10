package vc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// fakeSchemaResolver is a test double for vc.SchemaResolver: it returns a fixed
// resolution (or error) and records the reference it was asked to resolve.
type fakeSchemaResolver struct {
	resolved *vc.ResolvedSchema
	err      error
	gotRef   vc.SchemaRef
}

func (f *fakeSchemaResolver) ResolveSchema(_ context.Context, ref vc.SchemaRef) (*vc.ResolvedSchema, error) {
	f.gotRef = ref
	return f.resolved, f.err
}

// TestVerify_SchemaRef_DataIntegrity pins the credential.schema-ref verdict
// table: a schema reference refines the DataIntegrity axis by resolving the
// registered schema and comparing its content hash and declared format. The
// three-state discipline mirrors DID resolution — a definitive mismatch or a
// definitive miss (not-found / invalid-ref) fails; a transient resolver error,
// or the absence of a resolver when a reference is present, is indeterminate.
func TestVerify_SchemaRef_DataIntegrity(t *testing.T) {
	body := []byte(`{"type":"object"}`)
	sum := sha256.Sum256(body)
	goodHash := "sha256:" + hex.EncodeToString(sum[:])
	ref := vc.SchemaRef{
		ID:          "dplaax:schema/orders@2026-07-10-abcdef0123456789",
		Type:        "JsonSchema",
		ContentHash: goodHash,
	}

	cases := []struct {
		name     string
		ref      vc.SchemaRef      // schema on the credential (zero value = none)
		resolver vc.SchemaResolver // nil = WithSchemaResolver not set
		want     vc.ConfidenceState
	}{
		{"no ref, no resolver", vc.SchemaRef{}, nil, vc.ConfidenceVerified},
		{"ref present, no resolver", ref, nil, vc.ConfidenceIndeterminate},
		{"match", ref, &fakeSchemaResolver{resolved: &vc.ResolvedSchema{Format: "JsonSchema", Body: body}}, vc.ConfidenceVerified},
		{"hash mismatch", ref, &fakeSchemaResolver{resolved: &vc.ResolvedSchema{Format: "JsonSchema", Body: []byte("tampered")}}, vc.ConfidenceFailed},
		{"format mismatch", ref, &fakeSchemaResolver{resolved: &vc.ResolvedSchema{Format: "OpenAPI", Body: body}}, vc.ConfidenceFailed},
		{"not found", ref, &fakeSchemaResolver{err: vc.ErrSchemaNotFound}, vc.ConfidenceFailed},
		{"invalid ref", ref, &fakeSchemaResolver{err: vc.ErrSchemaInvalidRef}, vc.ConfidenceFailed},
		{"transient", ref, &fakeSchemaResolver{err: errors.New("registry unavailable")}, vc.ConfidenceIndeterminate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subj := sampleSubject()
			subj.Schema = tc.ref
			cred, err := vc.New(vc.CredentialFields{Issuer: issuerDID, ValidFrom: mustTime(t), Subject: subj})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			var opts []vc.VerifierOption
			if tc.resolver != nil {
				opts = append(opts, vc.WithSchemaResolver(tc.resolver))
			}
			v := vc.NewVerifier(local.New(), ed25519Verifier(), opts...)
			res, err := v.Verify(context.Background(), cred)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Axes.DataIntegrity != tc.want {
				t.Errorf("DataIntegrity = %v, want %v", res.Axes.DataIntegrity, tc.want)
			}
		})
	}
}

// TestSchemaRef_Addressing pins the schema-reference string grammar: the config
// short-form "<name>@<version>", its canonical wire URI "dplaax:schema/...",
// and their url-safe-segment validation. A malformed reference is
// ErrSchemaInvalidRef (a deterministic defect, not a transient miss).
func TestSchemaRef_Addressing(t *testing.T) {
	// SplitSchemaRef: the config short-form.
	splitCases := []struct {
		in        string
		name, ver string
		wantErr   bool
	}{
		{"orders@2026-07-10-abcdef0123456789", "orders", "2026-07-10-abcdef0123456789", false},
		{"a.b_c-d@1.0", "a.b_c-d", "1.0", false},
		{"noversion", "", "", true},  // no '@'
		{"@2026", "", "", true},      // empty name
		{"orders@", "", "", true},    // empty version
		{"or ders@1", "", "", true},  // space (not url-safe)
		{"orders@1/2", "", "", true}, // slash
		{"a@b@c", "", "", true},      // '@' in name (split on last '@' -> name "a@b" unsafe)
		{".@1", "", "", true},        // dot-only name (path-traversal token, stricter than registry)
		{"..@1", "", "", true},       // dotdot-only name
		{"orders@.", "", "", true},   // dot-only version
	}
	for _, tc := range splitCases {
		name, ver, err := vc.SplitSchemaRef(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("SplitSchemaRef(%q) = (%q,%q,nil), want error", tc.in, name, ver)
			} else if !errors.Is(err, vc.ErrSchemaInvalidRef) {
				t.Errorf("SplitSchemaRef(%q) err = %v, want ErrSchemaInvalidRef", tc.in, err)
			}
			continue
		}
		if err != nil || name != tc.name || ver != tc.ver {
			t.Errorf("SplitSchemaRef(%q) = (%q,%q,%v), want (%q,%q,nil)", tc.in, name, ver, err, tc.name, tc.ver)
		}
	}

	// SchemaURI / ParseSchemaURI round-trip.
	uri := vc.SchemaURI("orders", "2026-07-10-abcdef0123456789")
	if uri != "dplaax:schema/orders@2026-07-10-abcdef0123456789" {
		t.Fatalf("SchemaURI = %q, want dplaax:schema/orders@...", uri)
	}
	name, ver, err := vc.ParseSchemaURI(uri)
	if err != nil || name != "orders" || ver != "2026-07-10-abcdef0123456789" {
		t.Fatalf("ParseSchemaURI(%q) = (%q,%q,%v), want round-trip", uri, name, ver, err)
	}

	// ParseSchemaURI rejects a non-dplaax-schema ID as ErrSchemaInvalidRef.
	for _, bad := range []string{"orders@1", "https://x/s/1", "dplaax:schema/", "dplaax:schema/noversion", "dplaax:schema/.@1", "dplaax:schema/..@1"} {
		if _, _, err := vc.ParseSchemaURI(bad); !errors.Is(err, vc.ErrSchemaInvalidRef) {
			t.Errorf("ParseSchemaURI(%q) err = %v, want ErrSchemaInvalidRef", bad, err)
		}
	}
}

// TestVerify_SchemaRef_ResolverReceivesRef confirms the verifier hands the
// credential's own reference to the resolver (not a substitute).
func TestVerify_SchemaRef_ResolverReceivesRef(t *testing.T) {
	body := []byte(`{"type":"object"}`)
	sum := sha256.Sum256(body)
	ref := vc.SchemaRef{
		ID:          "dplaax:schema/orders@2026-07-10-abcdef0123456789",
		Type:        "JsonSchema",
		ContentHash: "sha256:" + hex.EncodeToString(sum[:]),
	}
	fr := &fakeSchemaResolver{resolved: &vc.ResolvedSchema{Format: "JsonSchema", Body: body}}
	subj := sampleSubject()
	subj.Schema = ref
	cred, err := vc.New(vc.CredentialFields{Issuer: issuerDID, ValidFrom: mustTime(t), Subject: subj})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithSchemaResolver(fr))
	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if fr.gotRef != ref {
		t.Errorf("resolver received %+v, want the credential's own ref %+v", fr.gotRef, ref)
	}
}
