// Package client is the production network client for a VCResolverService: it
// resolves pipeline credentials by content address and publishes issued
// credentials to the store. One type, both directions of the same service —
// resolution feeds a full-chain verifier (it satisfies the consumer-defined
// chainwalk.CredentialResolver contract structurally), publication feeds the
// audit store so a downstream full verifier can walk the chain.
//
// It imports only the generated client, the vc credential type, and connect —
// never the vcresolver service domain, and never pipeline/ (the compile-time
// chainwalk.CredentialResolver assertion lives in the consumer, cmd/standalone,
// to keep network → pipeline out of this package). The dependency points inward,
// so there is no service-to-service or layer cycle. Mirrors signer/client.
package client

import (
	"context"
	"encoding/json"
	"fmt"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/vc"
)

// Resolver is a node's handle to a VCResolverService: ResolveCredential fetches a
// credential by content address (satisfying chainwalk.CredentialResolver) and
// StoreCredential publishes an issued credential. Named for the service it fronts,
// as signer/client names its type Signer.
type Resolver struct {
	client vcpbconnect.VCResolverServiceClient
}

// New returns a Resolver over the given VCResolverService client. The L1 bearer,
// if any, is applied as a connect interceptor when the caller builds that client.
func New(c vcpbconnect.VCResolverServiceClient) *Resolver {
	return &Resolver{client: c}
}

// ResolveCredential fetches the credential held at contentAddress and decodes it.
// A not-found or transport error is returned as an error — chainwalk turns it into
// a chain hole (→ indeterminate); it never returns a nil credential with nil error.
func (r *Resolver) ResolveCredential(ctx context.Context, contentAddress string) (*vc.PipelinePassCredential, error) {
	resp, err := r.client.ResolveVC(ctx, connect.NewRequest(&vcpb.ResolveVCRequest{Hash: contentAddress}))
	if err != nil {
		return nil, err
	}
	var cred vc.PipelinePassCredential
	// Delegates to PipelinePassCredential.UnmarshalJSON, which routes the
	// decode through canon.StrictDecoder (decoder-hygiene-exempt).
	if err := json.Unmarshal(resp.Msg.GetCredential(), &cred); err != nil {
		return nil, fmt.Errorf("vcresolver/client: decode resolved credential: %w", err)
	}
	return &cred, nil
}

// StoredCredential is what a store assigned to a published credential: the body
// address successors link to, and the variant naming the exact signed form it
// admitted. Both are recomputed by the server from the bytes it received, so a
// publisher can check them against what it signed.
//
// It is a client-local type rather than the service's own: this package fronts
// a remote service and deliberately does not import the vcresolver domain (see
// the package doc).
type StoredCredential struct {
	// BodyAddress is the server-recomputed content address ("sha256:<hex>").
	BodyAddress string
	// WireVariantID names the exact wire bytes the store admitted
	// ("wire:v1:jcs-rfc8785:sha256:<hex>").
	WireVariantID string
}

// StoreCredential publishes cred to the store, recording upstreamEndpoint as the
// predecessor-fetch hint, and returns what the server assigned it.
func (r *Resolver) StoreCredential(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (StoredCredential, error) {
	// MarshalJSON returns the JCS-canonical bytes (as the envelope codec uses). json.Marshal
	// would re-escape <, >, & via Go's HTML escaping, breaking canonical-byte consumers.
	b, err := cred.MarshalJSON()
	if err != nil {
		return StoredCredential{}, fmt.Errorf("vcresolver/client: encode credential: %w", err)
	}
	resp, err := r.client.StoreVC(ctx, connect.NewRequest(&vcpb.StoreVCRequest{
		Credential:       b,
		UpstreamEndpoint: upstreamEndpoint,
	}))
	if err != nil {
		return StoredCredential{}, err
	}
	return StoredCredential{
		BodyAddress:   resp.Msg.GetHash(),
		WireVariantID: resp.Msg.GetWireVariantId(),
	}, nil
}
