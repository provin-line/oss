package vcresolver_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// These tests live at the FAÇADE, not per backend, and that placement is the
// point: identity, canonicality, write-once and winner selection are enforced
// in VariantStore, so they are proven once against every backend rather than
// re-asserted per implementation. The backend's own obligations (atomic
// create, faithful read-back, listing) are storecontract.Backend's.
//
// Several tests run against a HOSTILE backend — one that lies about what it
// holds. That is the model the façade is designed for: storage can be
// corrupted, rolled back, or simply wrong, and the caller must not be handed
// bytes that are not what it asked for.

func newStore(t *testing.T) *vcresolver.VariantStore {
	t.Helper()
	return vcresolver.NewVariantStore(memstore.NewBackend())
}

// credWithProof builds a signed wire credential. Distinct proofValues give
// distinct variants of ONE body — the situation this whole layer exists for.
func credWithProof(t *testing.T, processID, proofValue string) *vc.PipelinePassCredential {
	t.Helper()
	doc := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": processID},
	}
	if proofValue != "" {
		doc["proof"] = map[string]any{
			"type":               "DataIntegrityProof",
			"cryptosuite":        "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod",
			"created":            "2026-07-01T00:00:01Z",
			"proofValue":         proofValue,
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return &c
}

func mustPut(t *testing.T, s *vcresolver.VariantStore, cred *vc.PipelinePassCredential) (body, variant string) {
	t.Helper()
	body, variant, err := s.PutVariant(cred)
	if err != nil {
		t.Fatalf("PutVariant: %v", err)
	}
	return body, variant
}

func canonicalOf(t *testing.T, cred *vc.PipelinePassCredential) []byte {
	t.Helper()
	wire, err := cred.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// TestPutVariantRecomputesBothAddresses: the caller supplies bytes, never a
// name. Misfiling is therefore not a mistake this API can make — the addresses
// returned are derived from the bytes stored.
func TestPutVariantRecomputesBothAddresses(t *testing.T) {
	s := newStore(t)
	cred := credWithProof(t, "s1", "zA")
	body, variant := mustPut(t, s, cred)

	wantBody, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	wantVariant, err := cred.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	if body != wantBody || variant != wantVariant {
		t.Errorf("PutVariant = (%s, %s), want (%s, %s)", body, variant, wantBody, wantVariant)
	}
	got, err := s.GetVariant(body, variant)
	if err != nil {
		t.Fatalf("GetVariant: %v", err)
	}
	if !bytes.Equal(got, canonicalOf(t, cred)) {
		t.Errorf("GetVariant returned %s, want the canonical projection %s", got, canonicalOf(t, cred))
	}
}

// TestPutVariantDoesNotRetainTheCaller'sCredential — a caller mutating its
// credential after the put must not reach into stored evidence.
func TestPutVariantDoesNotRetainTheCallersCredential(t *testing.T) {
	s := newStore(t)
	cred := credWithProof(t, "s1", "zA")
	body, variant := mustPut(t, s, cred)
	before, err := s.GetVariant(body, variant)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the credential the caller still holds, then re-read.
	if err := cred.UnmarshalJSON(canonicalOf(t, credWithProof(t, "MUTATED", "zA"))); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetVariant(body, variant)
	if err != nil {
		t.Fatalf("GetVariant after the caller mutated its credential: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("mutating the caller's credential changed stored evidence")
	}
}

// TestGetVariantReturnsACallerOwnedCopy: two reads must not alias, or one
// caller could corrupt another's evidence in place.
func TestGetVariantReturnsACallerOwnedCopy(t *testing.T) {
	s := newStore(t)
	body, variant := mustPut(t, s, credWithProof(t, "s1", "zA"))
	first, err := s.GetVariant(body, variant)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	second, err := s.GetVariant(body, variant)
	if err != nil {
		t.Fatalf("GetVariant: %v", err)
	}
	if second[0] == 'X' {
		t.Error("a caller's scribble on returned bytes reached storage")
	}
}

// TestPutVariantIsIdempotent (identity-003's property, at the façade).
func TestPutVariantIsIdempotent(t *testing.T) {
	s := newStore(t)
	cred := credWithProof(t, "s1", "zA")
	body1, variant1 := mustPut(t, s, cred)
	body2, variant2, err := s.PutVariant(cred)
	if err != nil {
		t.Fatalf("re-admitting identical bytes must be idempotent, got: %v", err)
	}
	if body1 != body2 || variant1 != variant2 {
		t.Errorf("second put = (%s, %s), want (%s, %s)", body2, variant2, body1, variant1)
	}
	ids, err := s.ListVariantIDs(body1, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("variant set = %v, want exactly one entry", ids)
	}
}

// TestVariantSetIsAppendOnly is the whole point of the layer: neither arrival
// order can evict the other (identity-005 valid->invalid overwrite,
// identity-006 invalid front-run). Admission does not evaluate proofs, so
// "invalid" here is simply "a second signed form" — which is exactly why
// eviction would be unsafe.
func TestVariantSetIsAppendOnly(t *testing.T) {
	for _, order := range [][2]string{{"zA", "zB"}, {"zB", "zA"}} {
		t.Run(order[0]+"-then-"+order[1], func(t *testing.T) {
			s := newStore(t)
			first := credWithProof(t, "s1", order[0])
			second := credWithProof(t, "s1", order[1])
			bodyA, variantA := mustPut(t, s, first)
			bodyB, variantB := mustPut(t, s, second)

			if bodyA != bodyB {
				t.Fatalf("two proofs over one body landed on different bodies: %s != %s", bodyA, bodyB)
			}
			if variantA == variantB {
				t.Fatal("two different proofs share a variant id")
			}
			gotA, err := s.GetVariant(bodyA, variantA)
			if err != nil {
				t.Fatalf("the first variant is gone after a second was admitted: %v", err)
			}
			if !bytes.Equal(gotA, canonicalOf(t, first)) {
				t.Error("the first variant's bytes changed when the second was admitted")
			}
			gotB, err := s.GetVariant(bodyB, variantB)
			if err != nil {
				t.Fatalf("GetVariant (second): %v", err)
			}
			if !bytes.Equal(gotB, canonicalOf(t, second)) {
				t.Error("the second variant's bytes are not what was admitted")
			}
			ids, err := s.ListVariantIDs(bodyA, "", 10)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{variantA, variantB}
			sortTwo(want)
			if !reflect.DeepEqual(ids, want) {
				t.Errorf("variant set = %v, want %v", ids, want)
			}
		})
	}
}

// TestProjectionIsTheSetsMinimumRegardlessOfOrder: the winner is a function of
// the SET, so replay order cannot change it and two nodes holding the same
// variants project the same one.
func TestProjectionIsTheSetsMinimumRegardlessOfOrder(t *testing.T) {
	var winners []string
	for _, order := range [][2]string{{"zA", "zB"}, {"zB", "zA"}} {
		s := newStore(t)
		body, _ := mustPut(t, s, credWithProof(t, "s1", order[0]))
		mustPut(t, s, credWithProof(t, "s1", order[1]))
		got, err := s.Get(body)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		id, err := got.WireVariantID()
		if err != nil {
			t.Fatal(err)
		}
		winners = append(winners, id)

		ids, err := s.ListVariantIDs(body, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if id != ids[0] {
			t.Errorf("projection served %s, want the set's minimum %s", id, ids[0])
		}
	}
	if winners[0] != winners[1] {
		t.Errorf("admission order changed the projection: %s vs %s", winners[0], winners[1])
	}
}

// TestGetIsNotFoundForAnUnknownBody, and malformed input is InvalidArgument —
// a miss and a malformed request are different answers.
func TestGetAndGetVariantArgumentHandling(t *testing.T) {
	s := newStore(t)
	body, variant := mustPut(t, s, credWithProof(t, "s1", "zA"))
	absentBody := "sha256:" + strings.Repeat("0", 64)
	absentVariant := vc.WireVariantIDFromHex(strings.Repeat("0", 64))

	if _, err := s.Get(absentBody); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("Get(absent) = %v, want ErrNotFound", err)
	}
	if _, err := s.Get("not-a-hash"); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("Get(malformed) = %v, want ErrInvalidArgument", err)
	}
	if _, err := s.GetVariant(body, absentVariant); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("GetVariant(known body, absent variant) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetVariant(absentBody, variant); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("GetVariant(absent body) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetVariant(body, "wire:v9:nope:sha256:x"); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("GetVariant(malformed variant) = %v, want ErrInvalidArgument", err)
	}
	if _, err := s.GetVariant("not-a-hash", variant); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("GetVariant(malformed body) = %v, want ErrInvalidArgument", err)
	}
	if ids, err := s.ListVariantIDs(absentBody, "", 10); err != nil || len(ids) != 0 {
		t.Errorf("ListVariantIDs(unknown body) = %v (err %v), want an empty page and no error", ids, err)
	}
	if _, err := s.ListVariantIDs(body, "not-a-variant", 10); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("ListVariantIDs(malformed cursor) = %v, want ErrInvalidArgument", err)
	}
}

func sortTwo(s []string) {
	if s[0] > s[1] {
		s[0], s[1] = s[1], s[0]
	}
}

// --- hostile backend: storage that lies ---

// tamperBackend wraps a real backend and rewrites what reads return. It is how
// the tests reach states a healthy store cannot produce: a sha256 collision is
// not available, but corrupted storage is exactly what these checks are for.
type tamperBackend struct {
	vcresolver.VariantBackend
	variantBytes    func(held []byte) []byte
	projectionBytes func(held []byte) []byte
}

func (b *tamperBackend) ReadVariant(bodyHex, variantHex string) ([]byte, error) {
	held, err := b.VariantBackend.ReadVariant(bodyHex, variantHex)
	if err != nil || b.variantBytes == nil {
		return held, err
	}
	return b.variantBytes(held), nil
}

func (b *tamperBackend) ReadProjection(bodyHex string) ([]byte, error) {
	held, err := b.VariantBackend.ReadProjection(bodyHex)
	if err != nil || b.projectionBytes == nil {
		return held, err
	}
	return b.projectionBytes(held), nil
}

// TestGetVariantRejectsRespelledBytes is identity-004 at the façade: storage
// holding the same document spelled differently.
//
// What catches it here is the digest taken over the bytes AS STORED — re-spell
// them and the digest moves off the id they are filed under. (A read that
// parsed and re-canonicalized BEFORE digesting would not catch it: the
// re-canonicalization would put the bytes back and the digest would match.
// That is why readValidated digests the raw bytes and never a projection of
// them.) The canonical-equality check is load-bearing elsewhere — where the id
// is derived FROM the bytes rather than supplied with them; see
// TestPutVariantRefusesToAdoptANonCanonicalLegacyEntry.
func TestGetVariantRejectsRespelledBytes(t *testing.T) {
	inner := memstore.NewBackend()
	s := vcresolver.NewVariantStore(inner)
	cred := credWithProof(t, "s1", "zA")
	body, variant := mustPut(t, s, cred)

	respell := func(held []byte) []byte {
		return []byte(strings.Replace(string(held), "{", "{ ", 1))
	}
	// Sanity: the tampered bytes really are the same document under a
	// different spelling — otherwise this test would pass for the wrong
	// reason (a digest check would catch it and prove nothing).
	tampered := respell(canonicalOf(t, cred))
	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON(tampered); err != nil {
		t.Fatalf("fixture is not the same document: %v", err)
	}
	if got := vc.WireVariantIDOf(canonicalOf(t, &rt)); got != variant {
		t.Fatalf("fixture does not re-canonicalize to the same id (%s vs %s) — it would be caught by a digest check", got, variant)
	}

	tampering := vcresolver.NewVariantStore(&tamperBackend{VariantBackend: inner, variantBytes: respell})
	got, err := tampering.GetVariant(body, variant)
	if !errors.Is(err, vcresolver.ErrCorrupt) {
		t.Errorf("GetVariant on re-spelled bytes = (%s, %v), want ErrCorrupt", got, err)
	}
}

// TestGetVariantRejectsSubstitutedBytes: storage returning a DIFFERENT
// document under the requested id.
func TestGetVariantRejectsSubstitutedBytes(t *testing.T) {
	inner := memstore.NewBackend()
	s := vcresolver.NewVariantStore(inner)
	body, variant := mustPut(t, s, credWithProof(t, "s1", "zA"))
	other := canonicalOf(t, credWithProof(t, "s1", "zB"))

	tampering := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend: inner,
		variantBytes:   func([]byte) []byte { return other },
	})
	if _, err := tampering.GetVariant(body, variant); !errors.Is(err, vcresolver.ErrCorrupt) {
		t.Errorf("GetVariant on substituted bytes = %v, want ErrCorrupt", err)
	}
}

// TestPutVariantReportsCorruptionInsteadOfSucceeding: the write-once gate
// compares against what is actually held. If storage holds something else
// under this id, admitting silently would report success for evidence that is
// not there.
func TestPutVariantReportsCorruptionInsteadOfSucceeding(t *testing.T) {
	inner := memstore.NewBackend()
	s := vcresolver.NewVariantStore(inner)
	cred := credWithProof(t, "s1", "zA")
	mustPut(t, s, cred)
	other := canonicalOf(t, credWithProof(t, "s1", "zB"))

	tampering := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend: inner,
		variantBytes:   func([]byte) []byte { return other },
	})
	if _, _, err := tampering.PutVariant(cred); !errors.Is(err, vcresolver.ErrCorrupt) {
		t.Errorf("re-admitting over corrupt storage = %v, want ErrCorrupt", err)
	}
}

// --- the legacy flat slot: where canonical equality is the ONLY defence ---
//
// For a variant fetch, the caller names the id and the digest over the stored
// bytes settles it. The flat slot has no such witness: its id is DERIVED from
// whatever bytes are there, so a digest check compares a value against itself
// and can never fail. Only asking "are these bytes the canonical projection of
// the document they decode to" can reject them — and if nothing does,
// non-canonical bytes get filed as a variant under their own digest and every
// later fetch serves them, signed by nothing.

// TestPutVariantRefusesToAdoptANonCanonicalLegacyEntry: adopting is how legacy
// bytes enter the set, and it is the last moment anything can check them.
func TestPutVariantRefusesToAdoptANonCanonicalLegacyEntry(t *testing.T) {
	inner := memstore.NewBackend()
	seed := vcresolver.NewVariantStore(inner)
	legacy := credWithProof(t, "s1", "zA")
	body, _ := mustPut(t, seed, legacy)

	// A legacy flat slot holding the same document, re-spelled — what an
	// older writer with a different serializer would have left behind.
	respell := func(held []byte) []byte {
		return []byte(strings.Replace(string(held), "{", "{ ", 1))
	}
	store := vcresolver.NewVariantStore(&tamperBackend{VariantBackend: inner, projectionBytes: respell})

	_, _, err := store.PutVariant(credWithProof(t, "s1", "zB"))
	if !errors.Is(err, vcresolver.ErrCorrupt) {
		t.Fatalf("PutVariant over a non-canonical legacy entry = %v, want ErrCorrupt", err)
	}
	_ = body
}

// TestGetRefusesToServeANonCanonicalLegacyEntry: the read path derives the
// same id from the same bytes and must reach the same verdict — otherwise the
// projection would serve what admission refused.
//
// The body here is legacy-ONLY (a flat slot, no variants): that is the state
// in which the flat bytes are the answer rather than a pointer at one, so
// serving them without checking is serving un-covered bytes as evidence.
func TestGetRefusesToServeANonCanonicalLegacyEntry(t *testing.T) {
	inner := memstore.NewBackend()
	cred := credWithProof(t, "s1", "zA")
	body, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if err := inner.WriteProjection(strings.TrimPrefix(body, "sha256:"), canonicalOf(t, cred)); err != nil {
		t.Fatal(err)
	}
	store := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend: inner,
		projectionBytes: func(held []byte) []byte {
			return []byte(strings.Replace(string(held), "{", "{ ", 1))
		},
	})
	got, err := store.Get(body)
	if err == nil {
		t.Fatalf("Get served a non-canonical legacy entry: %s", canonicalOf(t, got))
	}
	if errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("Get laundered a non-canonical legacy entry into ErrNotFound: %v", err)
	}
}

// TestGetOnADamagedLegacyOnlyBodyDoesNotReadAsAbsent. A body whose only copy is
// a damaged flat entry must report damage. Answering ErrNotFound would launder
// a tampered credential into "this node never had it" — the store would report
// a gap in provenance where there is evidence of interference.
func TestGetOnADamagedLegacyOnlyBodyDoesNotReadAsAbsent(t *testing.T) {
	inner := memstore.NewBackend()
	cred := credWithProof(t, "s1", "zA")
	body, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	bodyHex := strings.TrimPrefix(body, "sha256:")
	// A legacy body: a flat slot and NO variants — the pre-slice layout.
	if err := inner.WriteProjection(bodyHex, canonicalOf(t, cred)); err != nil {
		t.Fatal(err)
	}
	store := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend:  inner,
		projectionBytes: func([]byte) []byte { return []byte(`{"not":"a credential"`) },
	})
	_, err = store.Get(body)
	if err == nil {
		t.Fatal("Get served a damaged legacy entry")
	}
	if errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("Get laundered a damaged legacy entry into ErrNotFound: %v", err)
	}
}

// TestGetServesTheSetWhenTheProjectionIsDamaged: a damaged derived pointer must
// not veto intact evidence — the winner still comes from the set.
func TestGetServesTheSetWhenTheProjectionIsDamaged(t *testing.T) {
	inner := memstore.NewBackend()
	seed := vcresolver.NewVariantStore(inner)
	cred := credWithProof(t, "s1", "zA")
	body, variant := mustPut(t, seed, cred)

	store := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend:  inner,
		projectionBytes: func([]byte) []byte { return []byte(`{"not":"a credential"`) },
	})
	got, err := store.Get(body)
	if err != nil {
		t.Fatalf("a damaged projection vetoed an intact variant set: %v", err)
	}
	gotID, err := got.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	if gotID != variant {
		t.Errorf("Get served %s, want the set's only variant %s", gotID, variant)
	}
}

// TestLegacyOnlyBodyReadsAsAOneElementSet is identity-007's property: bytes
// written before this slice existed are IN the set, without any migration pass
// having run. Reads consult the flat slot unconditionally, so nothing has to
// be swept for old evidence to remain reachable.
func TestLegacyOnlyBodyReadsAsAOneElementSet(t *testing.T) {
	backend := memstore.NewBackend()
	store := vcresolver.NewVariantStore(backend)
	cred := credWithProof(t, "s1", "zA")
	body, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	variant, err := cred.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	// The pre-slice layout: a body-only entry and no variants.
	if err := backend.WriteProjection(strings.TrimPrefix(body, "sha256:"), canonicalOf(t, cred)); err != nil {
		t.Fatal(err)
	}

	ids, err := store.ListVariantIDs(body, "", 10)
	if err != nil {
		t.Fatalf("ListVariantIDs: %v", err)
	}
	if !reflect.DeepEqual(ids, []string{variant}) {
		t.Errorf("legacy body's variant set = %v, want [%s]", ids, variant)
	}
	got, err := store.GetVariant(body, variant)
	if err != nil {
		t.Fatalf("a legacy body's bytes are not exact-fetchable under their own id: %v", err)
	}
	if !bytes.Equal(got, canonicalOf(t, cred)) {
		t.Error("a legacy body's bytes changed when read back")
	}
}

// TestRollbackWrittenFlatIsNotLost is Codex's finding: an OLD binary, run
// against this store after a rollback, writes the flat slot without knowing
// variants exist. Those bytes are held evidence. If the union were conditional
// on "this body has no variants", the next put would refresh the projection
// over them and they would be gone.
func TestRollbackWrittenFlatIsNotLost(t *testing.T) {
	backend := memstore.NewBackend()
	store := vcresolver.NewVariantStore(backend)
	first := credWithProof(t, "s1", "zA")
	body, variantA := mustPut(t, store, first)
	bodyHex := strings.TrimPrefix(body, "sha256:")

	// The rollback: an old binary overwrites the flat slot with a different
	// signed form of the same body, leaving the variant set untouched.
	rolledBack := credWithProof(t, "s1", "zB")
	variantB, err := rolledBack.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.WriteProjection(bodyHex, canonicalOf(t, rolledBack)); err != nil {
		t.Fatal(err)
	}

	// Re-upgraded: both are held, and both are exact-fetchable.
	ids, err := store.ListVariantIDs(body, "", 10)
	if err != nil {
		t.Fatalf("ListVariantIDs: %v", err)
	}
	want := []string{variantA, variantB}
	sortTwo(want)
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("variant set = %v, want %v — the rollback-written bytes are not in the set", ids, want)
	}
	if _, err := store.GetVariant(body, variantB); err != nil {
		t.Errorf("the rollback-written variant is not fetchable: %v", err)
	}

	// A later put must adopt them rather than overwrite them.
	if _, _, err := store.PutVariant(credWithProof(t, "s1", "zC")); err != nil {
		t.Fatalf("PutVariant: %v", err)
	}
	if _, err := store.GetVariant(body, variantB); err != nil {
		t.Errorf("the next put lost the rollback-written variant: %v", err)
	}
}

// TestListVariantIDsPagesAcrossTheFlatCandidate: the flat slot's variant must
// take its place in the ORDER, not be appended or dropped, or a paging caller
// would see it twice or never.
func TestListVariantIDsPagesAcrossTheFlatCandidate(t *testing.T) {
	backend := memstore.NewBackend()
	store := vcresolver.NewVariantStore(backend)
	body := ""
	var all []string
	for _, pv := range []string{"zA", "zB", "zC"} {
		b, id := mustPut(t, store, credWithProof(t, "s1", pv))
		body = b
		all = append(all, id)
	}
	// Leave one variant reachable ONLY through the flat slot, so the merge is
	// load-bearing for this listing.
	sortAll(all)
	if err := backend.WriteProjection(strings.TrimPrefix(body, "sha256:"), mustGetVariant(t, store, body, all[1])); err != nil {
		t.Fatal(err)
	}

	var paged []string
	cursor := ""
	for {
		page, err := store.ListVariantIDs(body, cursor, 2)
		if err != nil {
			t.Fatalf("ListVariantIDs: %v", err)
		}
		if len(page) == 0 {
			break
		}
		paged = append(paged, page...)
		cursor = page[len(page)-1]
		if len(page) < 2 {
			break
		}
	}
	if !reflect.DeepEqual(paged, all) {
		t.Errorf("paged listing = %v, want %v", paged, all)
	}
}

func mustGetVariant(t *testing.T, s *vcresolver.VariantStore, body, id string) []byte {
	t.Helper()
	wire, err := s.GetVariant(body, id)
	if err != nil {
		t.Fatalf("GetVariant(%s): %v", id, err)
	}
	return wire
}

func sortAll(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestGetRejectsACorruptProjection: the legacy read is not exempt from
// validation just because it is provisional.
func TestGetRejectsACorruptProjection(t *testing.T) {
	inner := memstore.NewBackend()
	s := vcresolver.NewVariantStore(inner)
	body, _ := mustPut(t, s, credWithProof(t, "s1", "zA"))

	tampering := vcresolver.NewVariantStore(&tamperBackend{
		VariantBackend: inner,
		variantBytes:   func([]byte) []byte { return []byte(`{"not":"a credential"`) },
	})
	if _, err := tampering.Get(body); err == nil {
		t.Error("Get served a corrupt projection")
	} else if errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("Get laundered damage into ErrNotFound: %v", err)
	}
}
