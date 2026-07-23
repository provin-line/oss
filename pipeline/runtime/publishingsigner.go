package runtime

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/vc"
)

// fullSigner is the producing-signer surface a publishingSigner wraps: a *vcdid.Signer
// satisfies both halves (a source uses SignFirstDrop, a chained loop SignChainPreserving).
type fullSigner interface {
	provenance.SourceSigner
	provenance.ChainedSigner
}

// StoredCredential is what a store assigned to a published credential: the
// body address successors link to, and the variant naming the exact signed
// form it admitted — the two fields publishIssuedCredential's round-trip
// check reads. Mirrored from
// network/pkg/services/vcresolver/client.StoredCredential so this package
// stays network-agnostic (network/ and pipeline/ never import each other,
// AGENTS.md rule 2); a Go interface method's return type must match exactly
// for structural satisfaction, so CredentialPublisher cannot simply reuse the
// network-side struct — cmd/pipeline's credentialPublisherAdapter (wiring.go)
// converts between the two.
type StoredCredential struct {
	// BodyAddress is the server-recomputed content address ("sha256:<hex>").
	BodyAddress string
	// WireVariantID names the exact wire bytes the store admitted
	// ("wire:v1:jcs-rfc8785:sha256:<hex>").
	WireVariantID string
}

// CredentialPublisher publishes an issued credential to the VC store and
// returns what the server assigned it. cmd/pipeline's wiring.go
// adapts a *vcresolverclient.Resolver to this interface (the exact method
// this package's earlier, unexported credentialPublisher named — exported as
// part of the boundary severance since it is now Deps' field type).
type CredentialPublisher interface {
	StoreCredential(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (StoredCredential, error)
}

// publishingSigner decorates a producing signer so each issued credential is published
// to the VC store (the audit substrate a downstream "full" verifier walks) right after
// signing and BEFORE the transport loop emits it downstream over NATS. It is fail-closed:
// a publication error — or a server-assigned identity that disagrees with the credential's
// own (the store did not store what was signed) — fails the sign, which the source/chained
// processor maps to StatusErrored, so the transport loop drops the event before emit. The
// chained loop passes its upstream-endpoint as the predecessor-fetch hint; a source
// FirstDrop has no predecessor, so its hint is empty.
type publishingSigner struct {
	inner            fullSigner
	publisher        CredentialPublisher
	upstreamEndpoint string
}

var (
	_ provenance.SourceSigner  = (*publishingSigner)(nil)
	_ provenance.ChainedSigner = (*publishingSigner)(nil)
)

func (p *publishingSigner) SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error) {
	cred, err := p.inner.SignFirstDrop(ctx, payload, inputHash, outputHash)
	if err != nil {
		return nil, err
	}
	if err := p.publish(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

func (p *publishingSigner) SignChainPreserving(ctx context.Context, payload []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	cred, err := p.inner.SignChainPreserving(ctx, payload, inputHash, outputHash, predecessor)
	if err != nil {
		return nil, err
	}
	if err := p.publish(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// SignAggregateFirstDrop forwards to the inner aggregate signer, then publishes the
// issued credential like the other two paths (an aggregate FirstDrop has no
// predecessor, so its publish hint is the configured upstreamEndpoint, same as a
// source FirstDrop).
func (p *publishingSigner) SignAggregateFirstDrop(ctx context.Context, payload []byte, outputHash string, sources []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	cred, err := p.inner.SignAggregateFirstDrop(ctx, payload, outputHash, sources)
	if err != nil {
		return nil, err
	}
	if err := p.publish(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// publish stores cred and verifies the round-trip: what the server recomputed must equal
// what was signed, else the store holds something else and a full verifier would resolve
// the wrong (or no) credential.
func (p *publishingSigner) publish(ctx context.Context, cred *vc.PipelinePassCredential) error {
	return publishIssuedCredential(ctx, p.publisher, cred, p.upstreamEndpoint)
}

// publishIssuedCredential stores cred to the remote VC store and verifies the round-trip:
// what the server recomputed must equal what was signed, else the store holds something
// else. Shared by publishingSigner and the aggregate emissionRegistrar (slice-17o, which
// reorders this publish to AFTER local self-audit registration — D-17o-3).
//
// The VARIANT is what settles it. The content address covers the body only, so it matches
// just as well when the store holds a different signed form of the same claims — which is
// the case this check exists to catch, and the one the address alone cannot see. Comparing
// the variant compares the whole document, signature included.
func publishIssuedCredential(ctx context.Context, publisher CredentialPublisher, cred *vc.PipelinePassCredential, upstreamEndpoint string) error {
	stored, err := publisher.StoreCredential(ctx, cred, upstreamEndpoint)
	if err != nil {
		return fmt.Errorf("publish issued credential to vc store: %w", err)
	}
	wantBody, err := cred.Hash()
	if err != nil {
		return fmt.Errorf("hash issued credential: %w", err)
	}
	if stored.BodyAddress != wantBody {
		return fmt.Errorf("vc store returned content address %q, want %q (credential not stored as signed)", stored.BodyAddress, wantBody)
	}
	wantVariant, err := cred.WireVariantID()
	if err != nil {
		return fmt.Errorf("derive issued credential variant: %w", err)
	}
	if stored.WireVariantID != wantVariant {
		return fmt.Errorf("vc store admitted variant %q, want %q (the stored document is not the one that was signed)", stored.WireVariantID, wantVariant)
	}
	return nil
}
