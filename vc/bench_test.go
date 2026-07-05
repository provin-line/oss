package vc_test

import (
	"context"
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// Paper 04 §6.2 Tables 4–5, Figs 2–3 (BENCH-RETAKE on provin): VC build/verify, VC-chain depth
// scaling, and multi-organization synthetic-chain build. Cryptographic work only (§6 preamble):
// signing uses an in-memory crypto.Signer (keystore/disk excluded); verification uses a real
// vc.Verifier over an in-memory local DID resolver (no network).

// benchSigner is an in-memory crypto.Signer over one raw Ed25519 key.
type benchSigner struct{ priv stded25519.PrivateKey }

var _ crypto.Signer = benchSigner{}

func (s benchSigner) Sign(_, _ string, data []byte) ([]byte, error) {
	return stded25519.Sign(s.priv, data), nil
}

const (
	benchOwner = "did:dplaax:reg:org:acme"
	benchKeyID = "signing"
	benchHash  = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func benchOrgDID(i int) string {
	return fmt.Sprintf("did:dplaax:reg:org:acme:pipeline:p%d:process:q%d", i, i)
}

// benchOrg is one signing organization: its issuer DID, an in-memory signer, and (for verify)
// its DID document seeded into the resolver.
type benchOrg struct {
	did    string
	vm     string
	signer benchSigner
	pub    []byte
}

func newBenchOrg(b *testing.B, i int) benchOrg {
	b.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	d := benchOrgDID(i)
	return benchOrg{did: d, vm: d + "#signing", signer: benchSigner{priv: stded25519.PrivateKey(kp.PrivateKey)}, pub: kp.PublicKey}
}

func benchDIDDoc(processDID, owner string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID:         processDID,
		Controller: owner,
		VerificationMethod: []did.VerificationMethod{{
			ID:         processDID + "#signing",
			Type:       "JsonWebKey2020",
			Controller: processDID,
			PublicKeyJWK: map[string]any{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		AssertionMethod: []string{processDID + "#signing"},
	})
}

func benchSubject() vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID: "p", ProcessID: "q",
		TransformationClaim: vc.ClaimConvert,
		InputHash:           benchHash,
		OutputHash:          benchHash,
	}
}

var sinkCred *vc.PipelinePassCredential

// BenchmarkVCBuild: sign+JCS+metadata for a chain-origin (no-chain) and a chain-preserving
// (with-chain) credential.
func BenchmarkVCBuild(b *testing.B) {
	org := newBenchOrg(b, 0)
	builder := vc.NewBuilder(org.signer)
	subject := benchSubject()

	b.Run("no-chain", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c, err := builder.BuildFirstDrop(org.did, benchKeyID, org.vm, subject, nil)
			if err != nil {
				b.Fatal(err)
			}
			sinkCred = c
		}
	})

	prev, err := builder.BuildFirstDrop(org.did, benchKeyID, org.vm, subject, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("with-chain", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c, err := builder.BuildChainPreserving(org.did, benchKeyID, org.vm, subject, prev, nil)
			if err != nil {
				b.Fatal(err)
			}
			sinkCred = c
		}
	})
}

// BenchmarkVCVerify: verify+JCS over a real vc.Verifier and in-memory DID resolver.
func BenchmarkVCVerify(b *testing.B) {
	org := newBenchOrg(b, 0)
	builder := vc.NewBuilder(org.signer)
	res := local.New()
	res.Add(benchDIDDoc(org.did, benchOwner, org.pub))
	res.Add(did.New(did.DocumentFields{ID: benchOwner, Controller: benchOwner}))
	verifier := vc.NewVerifier(res, ed25519.Verifier{})
	cred, err := builder.BuildFirstDrop(org.did, benchKeyID, org.vm, benchSubject(), nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, err := verifier.Verify(ctx, cred)
		if err != nil || r.Overall != vc.ConfidenceVerified {
			b.Fatalf("verify: overall=%v err=%v", r.Overall, err)
		}
	}
}

var benchDepths = []int{1, 5, 10, 25, 50}

// buildChain builds a depth-length single-org chain (FirstDrop + depth-1 ChainPreserving).
func buildChain(b *testing.B, builder *vc.Builder, org benchOrg, depth int) []*vc.PipelinePassCredential {
	subject := benchSubject()
	chain := make([]*vc.PipelinePassCredential, 0, depth)
	prev, err := builder.BuildFirstDrop(org.did, benchKeyID, org.vm, subject, nil)
	if err != nil {
		b.Fatal(err)
	}
	chain = append(chain, prev)
	for d := 1; d < depth; d++ {
		c, err := builder.BuildChainPreserving(org.did, benchKeyID, org.vm, subject, prev, nil)
		if err != nil {
			b.Fatal(err)
		}
		chain = append(chain, c)
		prev = c
	}
	return chain
}

// BenchmarkChainBuild (Fig 2): building a depth-length chain scales linearly with depth.
func BenchmarkChainBuild(b *testing.B) {
	org := newBenchOrg(b, 0)
	builder := vc.NewBuilder(org.signer)
	for _, depth := range benchDepths {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = buildChain(b, builder, org, depth)
			}
		})
	}
}

// BenchmarkChainVerify (Fig 2): per-VC verify cost is near-constant regardless of depth (each
// VC verifies independently — one Ed25519 verify + a previousCredential hash comparison).
func BenchmarkChainVerify(b *testing.B) {
	org := newBenchOrg(b, 0)
	builder := vc.NewBuilder(org.signer)
	res := local.New()
	res.Add(benchDIDDoc(org.did, benchOwner, org.pub))
	res.Add(did.New(did.DocumentFields{ID: benchOwner, Controller: benchOwner}))
	verifier := vc.NewVerifier(res, ed25519.Verifier{})
	ctx := context.Background()
	for _, depth := range benchDepths {
		chain := buildChain(b, builder, org, depth)
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, c := range chain {
					r, err := verifier.Verify(ctx, c)
					if err != nil || r.Overall != vc.ConfidenceVerified {
						b.Fatalf("verify: result=%v err=%v", r, err)
					}
				}
			}
		})
	}
}

// benchGrid is the paper §6.2 Table 5 / Figure 3 grid: orgs {2,5,10,20,50} × stages {1,3,5,10}.
var benchGrid = []struct{ orgs, stages int }{
	{2, 1}, {2, 3}, {2, 5}, {2, 10},
	{5, 1}, {5, 3}, {5, 5}, {5, 10},
	{10, 1}, {10, 3}, {10, 5}, {10, 10},
	{20, 1}, {20, 3}, {20, 5}, {20, 10},
	{50, 1}, {50, 3}, {50, 5}, {50, 10},
}

// newBenchOrgs returns n organizations with their builders, each with a fresh key.
func newBenchOrgs(b *testing.B, n int) ([]benchOrg, []*vc.Builder) {
	b.Helper()
	orgs := make([]benchOrg, n)
	builders := make([]*vc.Builder, n)
	for i := range orgs {
		orgs[i] = newBenchOrg(b, i)
		builders[i] = vc.NewBuilder(orgs[i].signer)
	}
	return orgs, builders
}

// BenchmarkMultiOrgChainBuild (Table 5): a synthetic chain spanning `orgs` organizations with
// `stages` process-boundary signatures each; total VCs = orgs*stages. Build latency scales
// linearly with total VCs; per-VC cost is near-constant across chain breadth.
func BenchmarkMultiOrgChainBuild(b *testing.B) {
	subject := benchSubject()
	for _, g := range benchGrid {
		orgs, builders := newBenchOrgs(b, g.orgs)
		total := g.orgs * g.stages
		b.Run(fmt.Sprintf("orgs=%d/stages=%d", g.orgs, g.stages), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				var prev *vc.PipelinePassCredential
				for o := 0; o < g.orgs; o++ {
					for s := 0; s < g.stages; s++ {
						var c *vc.PipelinePassCredential
						var err error
						if prev == nil {
							c, err = builders[o].BuildFirstDrop(orgs[o].did, benchKeyID, orgs[o].vm, subject, nil)
						} else {
							c, err = builders[o].BuildChainPreserving(orgs[o].did, benchKeyID, orgs[o].vm, subject, prev, nil)
						}
						if err != nil {
							b.Fatal(err)
						}
						prev = c
					}
				}
				_ = total
			}
		})
	}
}

// BenchmarkMultiOrgChainVerify (Fig 3): verifying every credential of a multi-organization
// synthetic chain, resolving each issuer's DID document from the in-memory resolver. Each VC
// verifies independently (one Ed25519 verify + a previousCredential hash comparison), so
// per-VC cost stays near-constant across chain breadth; total latency scales with orgs*stages.
func BenchmarkMultiOrgChainVerify(b *testing.B) {
	ctx := context.Background()
	for _, g := range benchGrid {
		orgs, builders := newBenchOrgs(b, g.orgs)
		res := local.New()
		res.Add(did.New(did.DocumentFields{ID: benchOwner, Controller: benchOwner}))
		for _, o := range orgs {
			res.Add(benchDIDDoc(o.did, benchOwner, o.pub))
		}
		verifier := vc.NewVerifier(res, ed25519.Verifier{})

		// Build the chain once outside the timed loop; only verification is measured.
		subject := benchSubject()
		chain := make([]*vc.PipelinePassCredential, 0, g.orgs*g.stages)
		var prev *vc.PipelinePassCredential
		for o := 0; o < g.orgs; o++ {
			for s := 0; s < g.stages; s++ {
				var c *vc.PipelinePassCredential
				var err error
				if prev == nil {
					c, err = builders[o].BuildFirstDrop(orgs[o].did, benchKeyID, orgs[o].vm, subject, nil)
				} else {
					c, err = builders[o].BuildChainPreserving(orgs[o].did, benchKeyID, orgs[o].vm, subject, prev, nil)
				}
				if err != nil {
					b.Fatal(err)
				}
				chain = append(chain, c)
				prev = c
			}
		}

		b.Run(fmt.Sprintf("orgs=%d/stages=%d", g.orgs, g.stages), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, c := range chain {
					r, err := verifier.Verify(ctx, c)
					if err != nil || r.Overall != vc.ConfidenceVerified {
						b.Fatalf("verify: result=%v err=%v", r, err)
					}
				}
			}
		})
	}
}
