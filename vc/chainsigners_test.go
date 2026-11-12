package vc_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// Issuers that are not Process DIDs: their keys come from a table.
const (
	issuerA = "did:example:issuer-a"
	issuerB = "did:example:issuer-b"
)

var (
	_ vc.IssuerKeys = vc.NewDIDDocumentIssuers(nil)
	_ vc.IssuerKeys = (*tableIssuers)(nil)
)

// keysChain issues an origin and a successor by issuerA and issuerB, under
// suite each (eddsa-jcs-2022 when empty), with the table of their keys.
func keysChain(t *testing.T, originSuite, childSuite string) (origin, child *vc.PipelinePassCredential, keys *tableIssuers) {
	t.Helper()
	kpA, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuerA, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpA}); err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(issuerB, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpB}); err != nil {
		t.Fatal(err)
	}
	builder := func(suite string) *vc.Builder {
		if suite == "" {
			return vc.NewBuilder(ks)
		}
		return vc.NewBuilder(ks, vc.WithCryptosuite(suite))
	}
	origin, err = builder(originSuite).BuildFirstDrop(issuerA, string(keystore.KeyIDSigning), issuerA+"#signing", vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "a", TransformationClaim: vc.ClaimConvert,
		InputHash: chainFixtureInput, OutputHash: "sha256:" + repeatHex("22"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	child, err = builder(childSuite).BuildChainPreserving(issuerB, string(keystore.KeyIDSigning), issuerB+"#signing", vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "b", TransformationClaim: vc.ClaimConvert,
		InputHash: "sha256:" + repeatHex("22"), OutputHash: "sha256:" + repeatHex("33"),
	}, origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys = &tableIssuers{
		keys:   map[string][]byte{issuerA + "#signing": kpA.PublicKey, issuerB + "#signing": kpB.PublicKey},
		owners: map[string]string{},
	}
	return origin, child, keys
}

// A chain whose issuers are not Process DIDs verifies by its keys: linked, in
// order, every signer verified, each under its contract and key. VerifyChain,
// which establishes Owners, does not verify it, and the Verifier's own issuer
// verifier is neither used nor changed.
func TestVerifyChainSigners_IssuersByTheirKeys(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	chain := []*vc.PipelinePassCredential{origin, child}
	res, err := v.VerifyChainSigners(context.Background(), keys, chain)
	if err != nil {
		t.Fatal(err)
	}
	if res.Links != nil || res.Order != nil || len(res.Signers) != 2 {
		t.Fatalf("Links, Order, len(Signers) = %v, %v, %d; want nil, nil, 2", res.Links, res.Order, len(res.Signers))
	}
	for i, issuer := range []string{issuerA, issuerB} {
		s := res.Signers[i]
		if s.State != vc.ConfidenceVerified || s.Err != nil || s.SuiteContract != vc.ContractW3CEdDSAJCS2022 ||
			s.Issuer != issuer || s.VerificationMethod != issuer+"#signing" {
			t.Errorf("Signers[%d] = %+v, want verified by %s#signing under the JCS contract", i, s, issuer)
		}
	}
	whole, err := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(keys)).VerifyChain(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	if whole.Overall == vc.ConfidenceVerified || whole.Axes.ChainConsistency == vc.ConfidenceVerified {
		t.Errorf("VerifyChain = %v (%+v), want chain consistency not verified for issuers with no Owner", whole.Overall, whole.Axes)
	}
	own, err := v.VerifySignerAuthenticity(context.Background(), asCredential(t, child))
	if err != nil {
		t.Fatal(err)
	}
	if own.State == vc.ConfidenceVerified {
		t.Error("the Verifier's own issuer verifier verified the credential: keys leaked into it")
	}
}

// Each entry of a chain under several contracts names its own.
func TestVerifyChainSigners_EachEntryNamesItsContract(t *testing.T) {
	origin, child, keys := keysChain(t, vc.CryptosuiteEdDSARDFC2022, "")
	res, err := vc.NewVerifier(local.New(), ed25519Verifier()).VerifyChainSigners(context.Background(), keys, []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.Links != nil || res.Order != nil {
		t.Fatalf("Links, Order = %v, %v; want nil", res.Links, res.Order)
	}
	if res.Signers[0].SuiteContract != vc.ContractW3CEdDSARDFC2022 || res.Signers[1].SuiteContract != vc.ContractW3CEdDSAJCS2022 {
		t.Errorf("contracts = %s, %s; want the RDFC and the JCS contract", res.Signers[0].SuiteContract, res.Signers[1].SuiteContract)
	}
}

// An eddsa-rdfc-2022 entry is held to its closed form: one not in it is a
// broken link at its position, and the signers are evaluated as for any
// chain.
func TestVerifyChainSigners_RDFCEntriesInTheirClosedForm(t *testing.T) {
	origin, child, r := rdfcChain(t, "procB")
	keys := &tableIssuers{keys: map[string][]byte{
		procAOrigin + "#signing":  signedPubOf(t, r, procAOrigin),
		procBSameOrg + "#signing": signedPubOf(t, r, procBSameOrg),
	}}
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	res, err := v.VerifyChainSigners(context.Background(), keys, []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.Links != nil || res.Order != nil || res.Signers[0].State != vc.ConfidenceVerified || res.Signers[1].State != vc.ConfidenceVerified {
		t.Fatalf("the closed form: Links %v, Order %v, Signers %v, %v; want nil, nil, verified, verified", res.Links, res.Order, res.Signers[0].State, res.Signers[1].State)
	}
	for _, tc := range formsOutsideTheClosedForm() {
		bent := reUnmarshal(t, child, tc.mutate)
		for shape, chain := range map[string][]*vc.PipelinePassCredential{
			"two": {origin, bent},
			"one": {bent},
		} {
			res, err := v.VerifyChainSigners(context.Background(), keys, chain)
			if err != nil {
				t.Fatal(err)
			}
			at := len(chain) - 1
			var linkErr *vc.ChainLinkError
			if !errors.As(res.Links, &linkErr) || linkErr.Index != at || len(res.Signers) != len(chain) {
				t.Errorf("%s, a chain of %s: Links %v with %d signers, want a *ChainLinkError at %d and %d signers", tc.name, shape, res.Links, len(res.Signers), at, len(chain))
			}
		}
	}
}

// Links is ValidateChainLinks' verdict on the chain, and the signers are
// evaluated whatever it is.
func TestVerifyChainSigners_LinksAreValidateChainLinks(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	for name, chain := range map[string][]*vc.PipelinePassCredential{
		"linked":                         {origin, child},
		"reordered":                      {child, origin},
		"a successor of another":         {origin, reUnmarshal(t, child, func(m map[string]any) { subjectOf(m)["previousCredential"] = foreignAddress })},
		"a successor from another input": {origin, reUnmarshal(t, child, func(m map[string]any) { subjectOf(m)["inputHash"] = foreignInput })},
	} {
		res, err := v.VerifyChainSigners(context.Background(), keys, chain)
		if err != nil {
			t.Fatal(err)
		}
		want := vc.ValidateChainLinks(chain)
		if fmt.Sprint(res.Links) != fmt.Sprint(want) {
			t.Errorf("%s: Links = %v, want %v", name, res.Links, want)
		}
		if want != nil && !errors.Is(res.Links, vc.ErrChainLinkBroken) {
			t.Errorf("%s: Links = %v, want ErrChainLinkBroken", name, res.Links)
		}
		if len(res.Signers) != len(chain) {
			t.Errorf("%s: %d signers for %d credentials", name, len(res.Signers), len(chain))
		}
	}
}

// Order names the first pair whose created times decrease or cannot be read,
// by the later credential's position (Index) and by the position of the
// credential the reported defect is in (FaultIndex: of a pair's defects, the
// earlier credential's missing proof first, then the later one's, then the
// earlier one's unreadable time, then the later one's, then a time that
// decreases), and agrees with VerifyChain's ordering verdict on the same
// chain.
func TestVerifyChainSigners_Order(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	created := func(c *vc.PipelinePassCredential, at string) *vc.PipelinePassCredential {
		return reUnmarshal(t, c, func(m map[string]any) { m["proof"].(map[string]any)["created"] = at })
	}
	noProof := func(c *vc.PipelinePassCredential) *vc.PipelinePassCredential {
		return reUnmarshal(t, c, func(m map[string]any) { delete(m, "proof") })
	}
	third := thirdCredential(t, child)
	for _, tc := range []struct {
		name  string
		chain []*vc.PipelinePassCredential
		at    int // -1: in order
		fault int
	}{
		{"in order", []*vc.PipelinePassCredential{origin, child}, -1, 0},
		{"equal times", []*vc.PipelinePassCredential{created(origin, "2026-11-01T00:00:00Z"), created(child, "2026-11-01T00:00:00Z")}, -1, 0},
		{"a successor earlier", []*vc.PipelinePassCredential{created(origin, "2026-11-02T00:00:00Z"), created(child, "2026-11-01T00:00:00Z")}, 1, 1},
		{"the origin's time unreadable", []*vc.PipelinePassCredential{created(origin, "yesterday"), child}, 1, 0},
		{"the successor's time unreadable", []*vc.PipelinePassCredential{origin, created(child, "yesterday")}, 1, 1},
		{"the origin unsigned", []*vc.PipelinePassCredential{noProof(origin), child}, 1, 0},
		{"the successor unsigned", []*vc.PipelinePassCredential{origin, noProof(child)}, 1, 1},
		{"both unsigned: the origin's is reported", []*vc.PipelinePassCredential{noProof(origin), noProof(child)}, 1, 0},
		{"the origin's time unreadable and the successor unsigned: the missing proof is reported", []*vc.PipelinePassCredential{created(origin, "yesterday"), noProof(child)}, 1, 1},
		{"both times unreadable: the origin's is reported", []*vc.PipelinePassCredential{created(origin, "yesterday"), created(child, "yesterday")}, 1, 0},
		{"the third earlier", []*vc.PipelinePassCredential{origin, child, created(third, "2000-01-01T00:00:00Z")}, 2, 2},
		{"two pairs out of order: the first is named", []*vc.PipelinePassCredential{created(origin, "2026-11-03T00:00:00Z"), created(child, "2026-11-02T00:00:00Z"), created(third, "2026-11-01T00:00:00Z")}, 1, 1},
		{"a middle time unreadable", []*vc.PipelinePassCredential{origin, created(child, "yesterday"), third}, 1, 1},
		{"one credential, unreadable", []*vc.PipelinePassCredential{created(origin, "yesterday")}, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := vc.NewVerifier(local.New(), ed25519Verifier()).VerifyChainSigners(context.Background(), &tableIssuers{}, tc.chain)
			if err != nil {
				t.Fatal(err)
			}
			if tc.at < 0 {
				if res.Order != nil {
					t.Errorf("Order = %v, want nil", res.Order)
				}
			} else {
				var orderErr *vc.ChainOrderError
				if !errors.As(res.Order, &orderErr) || orderErr.Index != tc.at || orderErr.Reason == "" || !errors.Is(res.Order, vc.ErrChainOrder) {
					t.Errorf("Order = %v, want a *ChainOrderError at %d (ErrChainOrder) with a reason", res.Order, tc.at)
				} else if orderErr.FaultIndex != tc.fault {
					t.Errorf("FaultIndex = %d, want %d", orderErr.FaultIndex, tc.fault)
				}
			}
			whole, err := vc.NewVerifier(r, ed25519Verifier()).VerifyChain(context.Background(), tc.chain)
			if err != nil {
				t.Fatal(err)
			}
			if inOrder := whole.Axes.ChainConsistency != vc.ConfidenceFailed; inOrder != (res.Order == nil) {
				t.Errorf("VerifyChain chain consistency %v, Order %v: they disagree", whole.Axes.ChainConsistency, res.Order)
			}
		})
	}
}

// Each entry is the evaluation VerifySignerAuthenticity makes of that
// credential under a Verifier whose issuer verifier is keys, with the same
// lifecycle registry.
func TestVerifyChainSigners_SignersAreVerifySignerAuthenticity(t *testing.T) {
	transient := errors.New("registry copy is being refreshed")
	_, otherPub := exampleCredential(t, issuerDID, nil)
	for _, tc := range []struct {
		name      string
		setup     func(s *tableIssuers)
		lifecycle vc.LifecycleRegistry
		notations bool
	}{
		{name: "every key"},
		{name: "no key for the successor", setup: func(s *tableIssuers) { delete(s.keys, issuerB+"#signing") }},
		{name: "another key for the origin", setup: func(s *tableIssuers) { s.keys[issuerA+"#signing"] = otherPub }},
		{name: "a key of another method", setup: func(s *tableIssuers) {
			s.answer = &vc.IssuerKey{ID: issuerA + "#other", PublicKey: s.keys[issuerA+"#signing"], Encoding: did.EncodingMultikey}
		}},
		{name: "a lookup that cannot answer", setup: func(s *tableIssuers) { s.keyErr = transient }},
		{name: "a Deprecated suite", lifecycle: phaseLifecycle{phase: vc.PhaseDeprecated}, notations: true},
		{name: "a Sunset suite", lifecycle: phaseLifecycle{phase: vc.PhaseSunset}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin, child, keys := keysChain(t, "", "")
			if tc.setup != nil {
				tc.setup(keys)
			}
			var opts []vc.VerifierOption
			if tc.lifecycle != nil {
				opts = append(opts, vc.WithLifecycleRegistry(tc.lifecycle))
			}
			chain := []*vc.PipelinePassCredential{origin, child}
			res, err := vc.NewVerifier(local.New(), ed25519Verifier(), opts...).VerifyChainSigners(context.Background(), keys, chain)
			if err != nil {
				t.Fatal(err)
			}
			alone := vc.NewVerifier(local.New(), ed25519Verifier(), append(opts, vc.WithIssuerVerifier(keys))...)
			for i, c := range chain {
				want, err := alone.VerifySignerAuthenticity(context.Background(), asCredential(t, c))
				if err != nil {
					t.Fatal(err)
				}
				got := res.Signers[i]
				if got.State != want.State || got.SuiteContract != want.SuiteContract || got.Issuer != want.Issuer ||
					got.VerificationMethod != want.VerificationMethod || fmt.Sprint(got.Notations) != fmt.Sprint(want.Notations) ||
					fmt.Sprint(got.Err) != fmt.Sprint(want.Err) {
					t.Errorf("Signers[%d] = %+v, want %+v", i, got, *want)
				}
				if tc.notations && len(got.Notations) == 0 {
					t.Errorf("Signers[%d] carries no notation", i)
				}
			}
		})
	}
}

// The issuer is read as a PipelinePassCredential reads it, a string: an
// issuer written as an object names none, as on Verify's signer-authenticity
// axis.
func TestVerifyChainSigners_TheIssuerIsAString(t *testing.T) {
	cred, pub := exampleCredential(t, map[string]any{"id": issuerDID}, nil)
	raw, err := cred.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pass vc.PipelinePassCredential
	if err := pass.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	keys := &tableIssuers{keys: map[string][]byte{vmID: pub}}
	res, err := vc.NewVerifier(local.New(), ed25519Verifier()).VerifyChainSigners(context.Background(), keys, []*vc.PipelinePassCredential{&pass})
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Signers[0]; s.State != vc.ConfidenceFailed || !errors.Is(s.Err, vc.ErrProofPolicy) {
		t.Errorf("Signers[0] = %+v, want failed, ErrProofPolicy", s)
	}
}

// No part stops the others: a chain whose links and order both break has
// both, and every signer.
func TestVerifyChainSigners_EveryPartIsEvaluated(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	created := func(c *vc.PipelinePassCredential, at string) *vc.PipelinePassCredential {
		return reUnmarshal(t, c, func(m map[string]any) { m["proof"].(map[string]any)["created"] = at })
	}
	chain := []*vc.PipelinePassCredential{created(child, "2026-11-02T00:00:00Z"), created(origin, "2026-11-01T00:00:00Z")}
	res, err := vc.NewVerifier(local.New(), ed25519Verifier()).VerifyChainSigners(context.Background(), keys, chain)
	if err != nil {
		t.Fatal(err)
	}
	var linkErr *vc.ChainLinkError
	var orderErr *vc.ChainOrderError
	if !errors.As(res.Links, &linkErr) || linkErr.Index != 0 || !errors.As(res.Order, &orderErr) || orderErr.Index != 1 || len(res.Signers) != 2 {
		t.Errorf("Links %v, Order %v, %d signers; want a broken link at 0, an order break at 1 and 2 signers", res.Links, res.Order, len(res.Signers))
	}
}

// cancellingKeys cancels its context on its call number at, and then answers
// with the context's error.
type cancellingKeys struct {
	inner  *tableIssuers
	cancel context.CancelFunc
	at     int
	calls  int
}

func (k *cancellingKeys) IssuerKey(ctx context.Context, cred *vc.Credential) (vc.IssuerKey, error) {
	k.calls++
	if k.calls == k.at {
		k.cancel()
		return vc.IssuerKey{}, ctx.Err()
	}
	return k.inner.IssuerKey(ctx, cred)
}

// A chain it cannot evaluate is a Go error: no credential, a nil one, no
// keys, or a context done before a credential is evaluated. A lookup
// cancelled inside the key source is that credential's indeterminate entry.
func TestVerifyChainSigners_WhatItCannotEvaluate(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	ctx := context.Background()
	for name, c := range map[string]struct {
		keys  vc.IssuerKeys
		chain []*vc.PipelinePassCredential
		want  error
	}{
		"no credential":    {keys, nil, vc.ErrChainEmpty},
		"a nil credential": {keys, []*vc.PipelinePassCredential{origin, nil}, vc.ErrChainEmpty},
	} {
		if res, err := v.VerifyChainSigners(ctx, c.keys, c.chain); res != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, %v; want nil and %v", name, res, err, c.want)
		}
	}
	if res, err := v.VerifyChainSigners(ctx, nil, []*vc.PipelinePassCredential{origin}); res != nil || err == nil {
		t.Errorf("nil keys: %v, %v; want nil and an error", res, err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if res, err := v.VerifyChainSigners(done, keys, []*vc.PipelinePassCredential{origin}); res != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("a context done: %v, %v; want nil and context.Canceled", res, err)
	}
	// Cancelled inside the first lookup: the next credential is not evaluated.
	first, cancelFirst := context.WithCancel(ctx)
	if res, err := v.VerifyChainSigners(first, &cancellingKeys{inner: keys, cancel: cancelFirst, at: 1}, []*vc.PipelinePassCredential{origin, child}); res != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled in the first lookup: %v, %v; want nil and context.Canceled", res, err)
	}
	// Cancelled inside the last lookup: that entry is indeterminate.
	last, cancelLast := context.WithCancel(ctx)
	res, err := v.VerifyChainSigners(last, &cancellingKeys{inner: keys, cancel: cancelLast, at: 2}, []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Signers[1]; s.State != vc.ConfidenceIndeterminate || !errors.Is(s.Err, context.Canceled) {
		t.Errorf("cancelled in the last lookup: Signers[1] = %+v, want indeterminate wrapping context.Canceled", s)
	}
}

// A *ChainOrderError is ErrChainOrder wherever it is wrapped, and names its
// credential.
func TestChainOrderError(t *testing.T) {
	e := &vc.ChainOrderError{Index: 2, Reason: "proof created is before its predecessor's"}
	wrapped := fmt.Errorf("wrapped: %w", e)
	if !errors.Is(wrapped, vc.ErrChainOrder) || errors.Is(wrapped, vc.ErrChainLinkBroken) {
		t.Errorf("errors.Is(%v): ErrChainOrder %t, ErrChainLinkBroken %t; want true, false", wrapped, errors.Is(wrapped, vc.ErrChainOrder), errors.Is(wrapped, vc.ErrChainLinkBroken))
	}
	if got, want := e.Error(), "vc: chain credential 2: proof created is before its predecessor's"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// State folds the three parts: a broken link, an order break or a failed
// signer is failed; else an indeterminate signer is indeterminate; else
// verified. A result with no signer, nil, and a signer whose State is none
// of the three are failed.
func TestChainSignersResult_State(t *testing.T) {
	ok := vc.SignerAuthenticityResult{State: vc.ConfidenceVerified}
	open := vc.SignerAuthenticityResult{State: vc.ConfidenceIndeterminate}
	bad := vc.SignerAuthenticityResult{State: vc.ConfidenceFailed}
	odd := vc.SignerAuthenticityResult{State: vc.ConfidenceState(99)}
	negative := vc.SignerAuthenticityResult{State: vc.ConfidenceState(-1)}
	link := &vc.ChainLinkError{Index: 1, Reason: "a broken link"}
	order := &vc.ChainOrderError{Index: 1, Reason: "out of order"}
	signers := func(s ...vc.SignerAuthenticityResult) []vc.SignerAuthenticityResult { return s }
	for name, c := range map[string]struct {
		r    *vc.ChainSignersResult
		want vc.ConfidenceState
	}{
		"every signer verified":            {&vc.ChainSignersResult{Signers: signers(ok, ok)}, vc.ConfidenceVerified},
		"one signer verified":              {&vc.ChainSignersResult{Signers: signers(ok)}, vc.ConfidenceVerified},
		"one indeterminate":                {&vc.ChainSignersResult{Signers: signers(ok, open)}, vc.ConfidenceIndeterminate},
		"one failed":                       {&vc.ChainSignersResult{Signers: signers(ok, bad)}, vc.ConfidenceFailed},
		"failed after indeterminate":       {&vc.ChainSignersResult{Signers: signers(open, bad)}, vc.ConfidenceFailed},
		"indeterminate after failed":       {&vc.ChainSignersResult{Signers: signers(bad, open)}, vc.ConfidenceFailed},
		"a broken link":                    {&vc.ChainSignersResult{Links: link, Signers: signers(ok, ok)}, vc.ConfidenceFailed},
		"out of order":                     {&vc.ChainSignersResult{Order: order, Signers: signers(ok, ok)}, vc.ConfidenceFailed},
		"a broken link, one indeterminate": {&vc.ChainSignersResult{Links: link, Signers: signers(ok, open)}, vc.ConfidenceFailed},
		"a state none of the three":        {&vc.ChainSignersResult{Signers: signers(ok, odd)}, vc.ConfidenceFailed},
		"a negative state":                 {&vc.ChainSignersResult{Signers: signers(open, negative)}, vc.ConfidenceFailed},
		"no signer":                        {&vc.ChainSignersResult{}, vc.ConfidenceFailed},
		"nil":                              {nil, vc.ConfidenceFailed},
	} {
		if got := c.r.State(); got != c.want {
			t.Errorf("%s: State = %v, want %v", name, got, c.want)
		}
	}
}

// State agrees with the parts of what VerifyChainSigners returns.
func TestChainSignersResult_StateOfWhatItReturns(t *testing.T) {
	origin, child, keys := keysChain(t, "", "")
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	ctx := context.Background()
	res, err := v.VerifyChainSigners(ctx, keys, []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatal(err)
	}
	if res.State() != vc.ConfidenceVerified {
		t.Errorf("a linked chain in order, every signer verified: State = %v, want verified", res.State())
	}
	delete(keys.keys, issuerB+"#signing")
	if res, err = v.VerifyChainSigners(ctx, keys, []*vc.PipelinePassCredential{origin, child}); err != nil || res.State() != vc.ConfidenceFailed {
		t.Errorf("no key for the successor: %v, %v; want failed", res.State(), err)
	}
	if res, err = v.VerifyChainSigners(ctx, keys, []*vc.PipelinePassCredential{child}); err != nil || res.Links == nil || res.State() != vc.ConfidenceFailed {
		t.Errorf("the successor alone: %+v, %v; want a broken link and failed", res, err)
	}
}
