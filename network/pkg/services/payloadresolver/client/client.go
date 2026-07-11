// Package client is the production network client for a PayloadService: it
// dereferences a by-reference payload by content address from a publisher's
// serving boundary. It signs every call in-band with wireauth (as a configured
// node identity), streams the response, caps the assembled size, and has the
// method shape the pipeline consumer seam requires.
//
// It imports only the generated client, connect, and crypto — never pipeline/
// (AGENTS.md layer rule: network and pipeline interact only over the wire). The
// compile-time assertion that *Resolver satisfies pipeline's PayloadResolver
// seam lives in the consumer (cmd/standalone), exactly as vcresolver/client
// keeps its chainwalk.CredentialResolver assertion there.
package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// opResolvePayload MUST match the publisher verifier's signed view.
const opResolvePayload = "ResolvePayload"

// DefaultMaxBytes caps an assembled payload when the caller sets no positive
// limit — a memory-safety bound, since the client buffers the whole payload to
// verify it against the content address.
const DefaultMaxBytes = 64 << 20 // 64 MiB

// ErrNotFound reports a definitive miss: the serving boundary authoritatively
// holds no payload at the content address (a publisher that agreed to
// by-reference delivery and cannot serve a payload it emitted has broken its
// retention obligation). Distinguished for observability; the consuming runtime
// treats it the same as any other fetch failure (a liveness failure).
var ErrNotFound = errors.New("payloadresolver/client: payload not found")

// Resolver is a node's handle to remote PayloadServices. One Resolver signs as a
// single configured identity and dials any serving boundary passed to
// ResolvePayload.
type Resolver struct {
	signer     crypto.Signer
	signerDID  string
	httpClient connect.HTTPClient
	maxBytes   int
}

// New returns a Resolver that signs as signerDID using signer and dials through
// httpClient (supply an SSRF-guarded client, e.g. core.URLGuard.HTTPClient()).
// A non-positive maxBytes falls back to DefaultMaxBytes.
func New(signer crypto.Signer, signerDID string, httpClient connect.HTTPClient, maxBytes int) *Resolver {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return &Resolver{signer: signer, signerDID: signerDID, httpClient: httpClient, maxBytes: maxBytes}
}

// ResolvePayload fetches and assembles the payload bytes held at contentHash on
// the serving boundary at upstreamEndpoint. It streams the response and aborts
// if the assembled size exceeds the configured cap (before the overflowing
// chunk is retained). A remote NotFound becomes ErrNotFound; any
// other transport failure is returned as-is (a liveness failure the runtime
// turns into a rejected/errored/dropped event). It never returns nil bytes with
// a nil error.
//
// The returned bytes carry NO trust — the caller's binding gate (sha256(payload)
// == the credential's outputHash) is the sole integrity check, so this client
// does not itself re-hash.
func (r *Resolver) ResolvePayload(ctx context.Context, upstreamEndpoint, contentHash string) ([]byte, error) {
	ap, err := r.proof(map[string]any{"content_hash": contentHash})
	if err != nil {
		return nil, err
	}
	svc := payloadpbconnect.NewPayloadServiceClient(r.httpClient, upstreamEndpoint)
	stream, err := svc.ResolvePayload(ctx, connect.NewRequest(&payloadpb.ResolvePayloadRequest{
		AuthProof:   ap,
		ContentHash: contentHash,
	}))
	if err != nil {
		return nil, mapRemoteErr(err)
	}
	defer stream.Close()
	var buf []byte
	for stream.Receive() {
		chunk := stream.Msg().GetChunk()
		// Reject empty chunks: a well-behaved server only frames non-empty slices
		// of a non-empty payload, and forbidding them makes the max-bytes cap a
		// real ITERATION bound — every accepted frame adds >= 1 byte, so the loop
		// cannot exceed maxBytes iterations. Without this, an untrusted upstream
		// (the exact by-reference threat model) could stream endless zero-length
		// frames, never tripping the byte cap, and hang the consuming subscription
		// goroutine indefinitely (head-of-line blocking every later event).
		if len(chunk) == 0 {
			return nil, fmt.Errorf("payloadresolver/client: serving boundary at %s streamed an empty chunk for %s (protocol violation)", upstreamEndpoint, contentHash)
		}
		if len(buf)+len(chunk) > r.maxBytes {
			return nil, fmt.Errorf("payloadresolver/client: payload at %s exceeds max-bytes %d", contentHash, r.maxBytes)
		}
		buf = append(buf, chunk...)
	}
	if err := stream.Err(); err != nil {
		return nil, mapRemoteErr(err)
	}
	return buf, nil
}

// proof signs op over fields as the configured identity and converts the
// wireauth.Proof to the wire AuthProof (issued_at as canonical second-precision
// UTC RFC 3339 — the exact form the publisher's strict codec accepts).
func (r *Resolver) proof(fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("payloadresolver/client: nonce: %w", err)
	}
	p, err := wireauth.Sign(r.signer, r.signerDID, opResolvePayload, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("payloadresolver/client: sign %s: %w", opResolvePayload, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}

// mapRemoteErr maps a remote NotFound to ErrNotFound (a broken publisher
// retention obligation, distinguished for observability); any other failure is
// returned as-is for the runtime to treat as a liveness failure.
func mapRemoteErr(err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}
