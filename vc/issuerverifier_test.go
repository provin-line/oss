package vc_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// stageIssuers establishes issuers from a table, as a product that registers
// its stages elsewhere would, with no DID documents at all.
type stageIssuers struct {
	keys      map[string][]byte // verificationMethod → Ed25519 key
	owners    map[string]string // issuer → Owner
	keyErr    error
	ownerErr  error
	keyCalls  int
	ownerSeen []string
	answer    *vc.IssuerKey // when set, returned as is
}

func (s *stageIssuers) IssuerKey(_ context.Context, cred *vc.Credential) (vc.IssuerKey, error) {
	s.keyCalls++
	if s.keyErr != nil {
		return vc.IssuerKey{}, s.keyErr
	}
	if s.answer != nil {
		return *s.answer, nil
	}
	vm := cred.Proof().VerificationMethod
	pub, ok := s.keys[vm]
	if !ok {
		return vc.IssuerKey{}, fmt.Errorf("no stage key %q: %w", vm, vc.ErrIssuerNotFound)
	}
	return vc.IssuerKey{ID: vm, PublicKey: pub, Encoding: did.EncodingMultikey}, nil
}

func (s *stageIssuers) Owner(_ context.Context, issuer string) (string, error) {
	s.ownerSeen = append(s.ownerSeen, issuer)
	if s.ownerErr != nil {
		return "", s.ownerErr
	}
	o, ok := s.owners[issuer]
	if !ok {
		return "", fmt.Errorf("no stage %q: %w", issuer, vc.ErrIssuerNotFound)
	}
	return o, nil
}

// stageChain is buildChainFixture's chain, verified through stageIssuers
// against an empty resolver: no process or owner document exists anywhere.
func stageChain(t *testing.T, originIssuer, childIssuer string) (origin, child *vc.PipelinePassCredential, s *stageIssuers) {
	t.Helper()
	origin, child, r := buildChainFixture(t, originIssuer, childIssuer)
	s = &stageIssuers{keys: map[string][]byte{}, owners: map[string]string{}}
	for _, issuer := range []string{originIssuer, childIssuer} {
		doc, err := r.Resolve(context.Background(), issuer)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := did.ExtractPublicKey(doc, issuer+"#signing", did.RelationshipAssertionMethod)
		if err != nil {
			t.Fatal(err)
		}
		s.keys[issuer+"#signing"] = pub
		s.owners[issuer] = ownerOf(t, issuer)
	}
	return origin, child, s
}

func TestIssuerVerifier_VerifiesAChainWithoutDIDDocuments(t *testing.T) {
	origin, child, s := stageChain(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s))
	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Fatalf("Overall = %v (%+v), want Verified", res.Overall, res.Axes)
	}
	// Without the verifier, the same chain cannot be verified: there are no
	// documents.
	res, err = vc.NewVerifier(local.New(), ed25519Verifier()).VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall == vc.ConfidenceVerified {
		t.Error("verified with no documents and no issuer verifier")
	}
}

// The Owner the verifier returns must be the Owner the issuer's DID names: a
// verifier cannot attribute a stage to another organization.
func TestIssuerVerifier_OwnerMustBeTheIssuersOwner(t *testing.T) {
	origin, child, s := stageChain(t, procAOrigin, procBSameOrg)
	s.owners[procBSameOrg] = ownerOf(t, procBOtherOrg)
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s))

	res, err := v.Verify(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceFailed {
		t.Errorf("ChainConsistency = %v, want Failed", res.Axes.ChainConsistency)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Errorf("SignerAuthenticity = %v, want Verified (the key is right; the owner is not)", res.Axes.SignerAuthenticity)
	}
	if _, err := v.AttributeOwner(context.Background(), procBSameOrg); !errors.Is(err, vc.ErrIssuerNotFound) {
		t.Errorf("AttributeOwner = %v, want an error wrapping ErrIssuerNotFound (an established negative)", err)
	}
	if _, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child}); !errors.Is(err, vc.ErrIssuerNotFound) {
		t.Errorf("ClassifyChain = %v, want an error wrapping ErrIssuerNotFound", err)
	}
}

func TestIssuerVerifier_AttributeAndClassifyThroughTheVerifier(t *testing.T) {
	origin, child, s := stageChain(t, procAOrigin, procBOtherOrg)
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s))
	owner, err := v.AttributeOwner(context.Background(), procBOtherOrg)
	if err != nil || owner != ownerOf(t, procBOtherOrg) {
		t.Fatalf("AttributeOwner = %q, %v; want %q", owner, err, ownerOf(t, procBOtherOrg))
	}
	class, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil || class != vc.ChainMultiOwnerDerived {
		t.Fatalf("ClassifyChain = %v, %v; want ChainMultiOwnerDerived", class, err)
	}
}

// ErrIssuerNotFound is an established negative (failed); any other error is
// transient (indeterminate) — the same taxonomy as the DID-document default.
func TestIssuerVerifier_ErrorTaxonomy(t *testing.T) {
	transient := errors.New("registry copy is being refreshed")
	for _, tc := range []struct {
		name           string
		keyErr, ownErr error
		wantSA, wantCC vc.ConfidenceState
	}{
		{"key not found", fmt.Errorf("x: %w", vc.ErrIssuerNotFound), nil, vc.ConfidenceFailed, vc.ConfidenceVerified},
		{"key transient", transient, nil, vc.ConfidenceIndeterminate, vc.ConfidenceVerified},
		{"owner not found", nil, fmt.Errorf("x: %w", vc.ErrIssuerNotFound), vc.ConfidenceVerified, vc.ConfidenceFailed},
		{"owner transient", nil, transient, vc.ConfidenceVerified, vc.ConfidenceIndeterminate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin, _, s := stageChain(t, procAOrigin, procBSameOrg)
			s.keyErr, s.ownerErr = tc.keyErr, tc.ownErr
			res, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)).Verify(context.Background(), origin)
			if err != nil {
				t.Fatal(err)
			}
			if res.Axes.SignerAuthenticity != tc.wantSA || res.Axes.ChainConsistency != tc.wantCC {
				t.Errorf("SignerAuthenticity, ChainConsistency = %v, %v; want %v, %v", res.Axes.SignerAuthenticity, res.Axes.ChainConsistency, tc.wantSA, tc.wantCC)
			}
		})
	}
}

// The proof policy runs before the verifier is asked for a key: a proof whose
// verificationMethod does not name the issuer fails without consulting it.
func TestIssuerVerifier_ProofPolicyComesFirst(t *testing.T) {
	origin, _, s := stageChain(t, procAOrigin, procBSameOrg)
	forged := reUnmarshal(t, origin, func(m map[string]any) {
		m["proof"].(map[string]any)["verificationMethod"] = procBSameOrg + "#signing"
	})
	res, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)).Verify(context.Background(), forged)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity = %v, want Failed", res.Axes.SignerAuthenticity)
	}
	if s.keyCalls != 0 {
		t.Errorf("the verifier was asked for a key %d times", s.keyCalls)
	}
}

// A key the verifier returns that did not make the proof fails it.
func TestIssuerVerifier_WrongKeyFails(t *testing.T) {
	origin, _, s := stageChain(t, procAOrigin, procBSameOrg)
	s.keys[procAOrigin+"#signing"] = s.keys[procBSameOrg+"#signing"]
	res, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)).Verify(context.Background(), origin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity = %v, want Failed", res.Axes.SignerAuthenticity)
	}
}

// The type-agnostic entry point takes its key from the same verifier.
func TestIssuerVerifier_SignerAuthenticityOfAnyCredential(t *testing.T) {
	cred, pub := exampleCredential(t, issuerDID, nil)
	s := &stageIssuers{keys: map[string][]byte{vmID: pub}}
	res, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)).VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceVerified || s.keyCalls != 1 {
		t.Errorf("State = %v after %d key calls, want Verified after 1", res.State, s.keyCalls)
	}
}

// NewDIDDocumentIssuers is the default: a verifier given it explicitly agrees
// with one given none, case by case.
func TestNewDIDDocumentIssuers_IsTheDefault(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBOtherOrg)
	broken := local.New()
	broken.Add(didDoc(procAOrigin, ownerOf(t, procBOtherOrg), procAOrigin+"#signing", signedPubOf(t, r, procAOrigin)))
	for _, docs := range []*local.Resolver{r, broken, local.New()} {
		for _, chain := range [][]*vc.PipelinePassCredential{{origin}, {origin, child}} {
			def, err := vc.NewVerifier(docs, ed25519Verifier()).VerifyChain(context.Background(), chain)
			if err != nil {
				t.Fatal(err)
			}
			explicit, err := vc.NewVerifier(docs, ed25519Verifier(), vc.WithIssuerVerifier(vc.NewDIDDocumentIssuers(docs))).VerifyChain(context.Background(), chain)
			if err != nil {
				t.Fatal(err)
			}
			if def.Axes != explicit.Axes || def.SuiteContract != explicit.SuiteContract {
				t.Errorf("default %+v, explicit %+v", def.Axes, explicit.Axes)
			}
		}
	}
}

func signedPubOf(t *testing.T, r *local.Resolver, issuer string) []byte {
	t.Helper()
	doc, err := r.Resolve(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := did.ExtractPublicKey(doc, issuer+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// The key the verifier returns must be the one the proof names: a proof naming
// a method the issuer does not have fails, through the default and through a
// replaced verifier, and a key returned under another id is not used.
func TestIssuerVerifier_TheKeyIsTheOneTheProofNames(t *testing.T) {
	origin, _, s := stageChain(t, procAOrigin, procBSameOrg)
	_, _, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	renamed := reUnmarshal(t, origin, func(m map[string]any) {
		m["proof"].(map[string]any)["verificationMethod"] = procAOrigin + "#registry"
	})
	for name, v := range map[string]*vc.Verifier{
		"default":  vc.NewVerifier(r, ed25519Verifier()),
		"replaced": vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)),
	} {
		res, err := v.Verify(context.Background(), renamed)
		if err != nil {
			t.Fatal(err)
		}
		if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
			t.Errorf("%s: SignerAuthenticity = %v for an unknown method, want Failed", name, res.Axes.SignerAuthenticity)
		}
	}
	// A verifier that answers with the right key under another id.
	right := s.keys[procAOrigin+"#signing"]
	for name, answer := range map[string]vc.IssuerKey{
		"another id": {ID: procAOrigin + "#registry", PublicKey: right, Encoding: did.EncodingMultikey},
		"no id":      {PublicKey: right, Encoding: did.EncodingMultikey},
		"zero":       {},
	} {
		s.answer = &answer
		res, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s)).Verify(context.Background(), origin)
		if err != nil {
			t.Fatal(err)
		}
		if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
			t.Errorf("%s: SignerAuthenticity = %v, want Failed", name, res.Axes.SignerAuthenticity)
		}
	}
}

// The Owner is not asked for an issuer that is not a Process DID: the
// Verifier refuses it first.
func TestIssuerVerifier_OwnerOfANonProcessIssuerIsNotAsked(t *testing.T) {
	_, _, s := stageChain(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s))
	if _, err := v.AttributeOwner(context.Background(), ownerDID); !errors.Is(err, vc.ErrIssuerNotFound) {
		t.Errorf("AttributeOwner(owner DID) = %v, want ErrIssuerNotFound", err)
	}
	if len(s.ownerSeen) != 0 {
		t.Errorf("Owner was asked for %v", s.ownerSeen)
	}
}

// WithIssuerVerifier(nil) keeps the default.
func TestWithIssuerVerifier_NilKeepsTheDefault(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	res, err := vc.NewVerifier(r, ed25519Verifier(), vc.WithIssuerVerifier(nil)).VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall = %v, want Verified", res.Overall)
	}
}
