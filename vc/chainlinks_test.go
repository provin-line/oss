package vc_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/provin-line/oss/vc"
)

// The origin input of buildChainFixture's chain: the origin's inputHash.
const chainFixtureInput = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// Well-formed content addresses that no fixture credential has.
var (
	foreignAddress = "sha256:" + repeatHex("de")
	foreignInput   = "sha256:" + repeatHex("99")
)

func subjectOf(m map[string]any) map[string]any { return m["credentialSubject"].(map[string]any) }

// thirdCredential extends origin → child with a credential linked to child.
// It is unsigned for its new body; the links do not read signatures.
func thirdCredential(t *testing.T, child *vc.PipelinePassCredential) *vc.PipelinePassCredential {
	t.Helper()
	h, err := child.Hash()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := child.Subject()
	if err != nil {
		t.Fatal(err)
	}
	return reUnmarshal(t, child, func(m map[string]any) {
		subjectOf(m)["previousCredential"] = h
		subjectOf(m)["inputHash"] = cs.OutputHash
		subjectOf(m)["outputHash"] = "sha256:" + repeatHex("44")
	})
}

func TestValidateChainLinksAndFrom_GenuineChains(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	for _, chain := range [][]*vc.PipelinePassCredential{{origin}, {origin, child}, {origin, child, thirdCredential(t, child)}} {
		if err := vc.ValidateChainLinks(chain); err != nil {
			t.Errorf("ValidateChainLinks(%d): %v", len(chain), err)
		}
		if err := vc.ValidateChainFrom(chain, chainFixtureInput); err != nil {
			t.Errorf("ValidateChainFrom(%d): %v", len(chain), err)
		}
	}
	// A null previousCredential at the origin is no predecessor.
	nullPrev := reUnmarshal(t, origin, func(m map[string]any) { subjectOf(m)["previousCredential"] = nil })
	if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{nullPrev}); err != nil {
		t.Errorf("origin with a null previousCredential: %v", err)
	}
}

// The links are checked without the signatures: a chain whose proofs are gone
// or forged still links, and VerifyChain (which checks the proofs) refuses it.
func TestValidateChainLinks_ReadsNoSignature(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	unsignedChild := reUnmarshal(t, child, func(m map[string]any) { delete(m, "proof") })
	forgedOrigin := reUnmarshal(t, origin, func(m map[string]any) {
		m["proof"].(map[string]any)["proofValue"] = "z3FakeSignatureFakeSignatureFakeSignature"
	})
	chain := []*vc.PipelinePassCredential{forgedOrigin, unsignedChild}
	if err := vc.ValidateChainFrom(chain, chainFixtureInput); err != nil {
		t.Fatalf("ValidateChainFrom: %v", err)
	}
	res, err := vc.NewVerifier(r, ed25519Verifier()).VerifyChain(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("VerifyChain SignerAuthenticity = %v, want Failed", res.Axes.SignerAuthenticity)
	}
}

// A prefix of a linked chain is linked: the links cannot tell that the tail is
// missing.
func TestValidateChainLinks_APrefixLinks(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	full := []*vc.PipelinePassCredential{origin, child, thirdCredential(t, child)}
	for n := 1; n <= len(full); n++ {
		if err := vc.ValidateChainLinks(full[:n]); err != nil {
			t.Errorf("prefix of %d: %v", n, err)
		}
	}
}

// The origin's input is checked by ValidateChainFrom only: an origin from
// another input, or without one (an aggregation's), links.
func TestValidateChainFrom_BindsTheOriginInput(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	for name, mutate := range map[string]func(map[string]any){
		"another input": func(m map[string]any) { subjectOf(m)["inputHash"] = foreignInput },
		"no input":      func(m map[string]any) { delete(subjectOf(m), "inputHash") },
	} {
		o := reUnmarshal(t, origin, mutate)
		if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{o}); err != nil {
			t.Errorf("%s: ValidateChainLinks: %v", name, err)
		}
		err := vc.ValidateChainFrom([]*vc.PipelinePassCredential{o}, chainFixtureInput)
		var linkErr *vc.ChainLinkError
		if !errors.As(err, &linkErr) || linkErr.Index != 0 || !errors.Is(err, vc.ErrChainLinkBroken) {
			t.Errorf("%s: ValidateChainFrom = %v, want a *ChainLinkError at 0, which is ErrChainLinkBroken", name, err)
		}
	}
	if err := vc.ValidateChainFrom([]*vc.PipelinePassCredential{origin, child}, foreignInput); err == nil {
		t.Error("ValidateChainFrom accepted a chain from another input")
	}
}

// Each broken link is reported as a *ChainLinkError naming the first
// credential whose link does not hold. Where every credential is well formed
// (VerifyChain's per-credential data integrity is verified), VerifyChain fails
// the data-integrity axis on the same chain, so its link step is what fails it.
func TestValidateChainLinks_BrokenLinks(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	third := thirdCredential(t, child)
	breakPrev := func(c *vc.PipelinePassCredential) *vc.PipelinePassCredential {
		return reUnmarshal(t, c, func(m map[string]any) { subjectOf(m)["previousCredential"] = foreignAddress })
	}
	cases := []struct {
		name       string
		chain      []*vc.PipelinePassCredential
		wantIndex  int
		wellFormed bool
	}{
		{"origin carries a predecessor", []*vc.PipelinePassCredential{reUnmarshal(t, origin, func(m map[string]any) {
			subjectOf(m)["previousCredential"] = foreignAddress
		})}, 0, true},
		{"origin carries a non-string predecessor", []*vc.PipelinePassCredential{reUnmarshal(t, origin, func(m map[string]any) {
			subjectOf(m)["previousCredential"] = 42
		})}, 0, false},
		{"origin carries an empty predecessor", []*vc.PipelinePassCredential{reUnmarshal(t, origin, func(m map[string]any) {
			subjectOf(m)["previousCredential"] = ""
		})}, 0, false},
		{"successor names another predecessor", []*vc.PipelinePassCredential{origin, breakPrev(child)}, 1, true},
		{"successor without a predecessor", []*vc.PipelinePassCredential{origin, reUnmarshal(t, child, func(m map[string]any) {
			delete(subjectOf(m), "previousCredential")
		})}, 1, true},
		{"successor from another input", []*vc.PipelinePassCredential{origin, reUnmarshal(t, child, func(m map[string]any) {
			subjectOf(m)["inputHash"] = foreignInput
		})}, 1, true},
		{"successor without a subject", []*vc.PipelinePassCredential{origin, reUnmarshal(t, child, func(m map[string]any) {
			m["credentialSubject"] = "not-an-object"
		})}, 1, false},
		{"source commitment leaves out the predecessor", []*vc.PipelinePassCredential{origin, reUnmarshal(t, child, func(m map[string]any) {
			subjectOf(m)["derived_from"] = []any{"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:other"}
			subjectOf(m)["source_root"] = "f1220" + repeatHex("0f")
			subjectOf(m)["source_root_canonical"] = "jcs-rfc8785"
		})}, 1, true},
		{"records out of order", []*vc.PipelinePassCredential{child, origin}, 0, true},
		{"a break at the third credential", []*vc.PipelinePassCredential{origin, child, breakPrev(third)}, 2, true},
		{"two breaks: the first is reported", []*vc.PipelinePassCredential{origin, breakPrev(child), breakPrev(third)}, 1, true},
	}
	v := vc.NewVerifier(r, ed25519Verifier())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := vc.ValidateChainLinks(tc.chain)
			var linkErr *vc.ChainLinkError
			if !errors.As(err, &linkErr) {
				t.Fatalf("err = %v, want a *ChainLinkError", err)
			}
			if linkErr.Index != tc.wantIndex || linkErr.Reason == "" {
				t.Errorf("Index, Reason = %d, %q; want %d and a reason", linkErr.Index, linkErr.Reason, tc.wantIndex)
			}
			if !errors.Is(err, vc.ErrChainLinkBroken) || errors.Is(err, vc.ErrChainMalformed) {
				t.Errorf("err = %v, want ErrChainLinkBroken and not ErrChainMalformed", err)
			}
			if !tc.wellFormed {
				return
			}
			for i, c := range tc.chain {
				r, err := v.Verify(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				if r.Axes.DataIntegrity != vc.ConfidenceVerified {
					t.Fatalf("credential %d fails data integrity on its own (%v): the case does not reach the link step", i, r.Axes.DataIntegrity)
				}
			}
			res, err := v.VerifyChain(context.Background(), tc.chain)
			if err != nil {
				t.Fatal(err)
			}
			if res.Axes.DataIntegrity != vc.ConfidenceFailed {
				t.Errorf("VerifyChain DataIntegrity = %v, want Failed on the same chain", res.Axes.DataIntegrity)
			}
		})
	}
}

// A successor's source commitment cannot include a predecessor that names no
// issuer: an empty issuer matches nothing.
func TestValidateChainLinks_SourceCommitmentOfAnIssuerlessPredecessor(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	bare := reUnmarshal(t, origin, func(m map[string]any) { delete(m, "issuer") })
	h, err := bare.Hash()
	if err != nil {
		t.Fatal(err)
	}
	relinked := reUnmarshal(t, child, func(m map[string]any) {
		subjectOf(m)["previousCredential"] = h
		subjectOf(m)["derived_from"] = []any{""}
		subjectOf(m)["source_root"] = "f1220" + repeatHex("0f")
		subjectOf(m)["source_root_canonical"] = "jcs-rfc8785"
	})
	var linkErr *vc.ChainLinkError
	if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{bare, relinked}); !errors.As(err, &linkErr) || linkErr.Index != 1 {
		t.Errorf("err = %v, want a *ChainLinkError at 1", err)
	}
}

// Nothing to link is an error of another kind than a broken link:
// ErrChainMalformed. An empty origin input is the caller's argument, not the
// chain: it is neither.
func TestValidateChainLinksAndFrom_NothingToLink(t *testing.T) {
	origin, _, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	for name, c := range map[string]struct {
		err       error
		malformed bool
	}{
		"empty chain":          {vc.ValidateChainLinks(nil), true},
		"empty chain (from)":   {vc.ValidateChainFrom(nil, chainFixtureInput), true},
		"nil origin":           {vc.ValidateChainLinks([]*vc.PipelinePassCredential{nil, origin}), true},
		"nil successor":        {vc.ValidateChainLinks([]*vc.PipelinePassCredential{origin, nil}), true},
		"nil successor (from)": {vc.ValidateChainFrom([]*vc.PipelinePassCredential{origin, nil}, chainFixtureInput), true},
		"empty origin input":   {vc.ValidateChainFrom([]*vc.PipelinePassCredential{origin}, ""), false},
	} {
		var linkErr *vc.ChainLinkError
		if c.err == nil || errors.As(c.err, &linkErr) || errors.Is(c.err, vc.ErrChainLinkBroken) {
			t.Errorf("%s: err = %v, want an error that is not a *ChainLinkError nor ErrChainLinkBroken", name, c.err)
		}
		if errors.Is(c.err, vc.ErrChainMalformed) != c.malformed {
			t.Errorf("%s: err = %v, errors.Is ErrChainMalformed = %t, want %t", name, c.err, !c.malformed, c.malformed)
		}
	}
	// The texts are the ones these errors had before they were
	// ErrChainMalformed.
	for err, want := range map[error]string{
		vc.ValidateChainLinks(nil):                                       "vc: empty chain",
		vc.ValidateChainLinks([]*vc.PipelinePassCredential{origin, nil}): "vc: chain credential 1 is nil",
	} {
		if err.Error() != want {
			t.Errorf("err = %q, want %q", err, want)
		}
	}
}

// A *ChainLinkError is ErrChainLinkBroken wherever it is wrapped, and is
// nothing else of this package's.
func TestChainLinkError_IsErrChainLinkBroken(t *testing.T) {
	e := &vc.ChainLinkError{Index: 1, Reason: "inputHash is not the predecessor's outputHash"}
	wrapped := fmt.Errorf("stage s2: %w", e)
	if !errors.Is(e, vc.ErrChainLinkBroken) || !errors.Is(wrapped, vc.ErrChainLinkBroken) {
		t.Errorf("errors.Is(%v, ErrChainLinkBroken) = false", wrapped)
	}
	for _, other := range []error{vc.ErrChainMalformed, vc.ErrIssuerNotFound, vc.ErrSignatureInvalid} {
		if errors.Is(wrapped, other) {
			t.Errorf("errors.Is(%v, %v) = true", wrapped, other)
		}
	}
	var got *vc.ChainLinkError
	if !errors.As(wrapped, &got) || got != e {
		t.Errorf("errors.As lost the *ChainLinkError")
	}
}
