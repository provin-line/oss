// Package resolver defines DID Document resolution. Implementations live in
// subpackages; grpc and multi are planned — their entries describe intended
// contract, not present code:
//
//   - local: in-memory store for tests and fixtures (implemented)
//   - cache: TTL- and byte-bounded caching decorator over any Resolver
//     (implemented)
//   - grpc:  (planned) ConnectRPC call to a registry's DIDService; validates
//     that the returned document ID equals the requested DID
//     (registry-substitution defense)
//   - multi: (planned) home-registry-first with fallback to additional
//     registries on connection errors ONLY — application errors (not-found,
//     permission) are authoritative and short-circuit, so fallback never masks
//     a configuration error on the negative path
package resolver

import (
	"context"
	"errors"

	"github.com/provin-line/oss/did"
)

// Resolver resolves a DID string to its DID Document.
type Resolver interface {
	Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error)
}

// ErrNotFound is the definitive-absence sentinel of the Resolve contract: an
// implementation returns an error wrapping ErrNotFound (per errors.Is) when
// the authoritative source states the DID does not exist — a registry 404, a
// local-store miss. Every other resolution error is treated by
// confidence-classifying consumers (vc.Verifier) as transient — indeterminate,
// retryable — so an implementation must NOT wrap this sentinel on paths that
// can fail non-definitively (timeout, connection refused, 5xx, parse failure).
var ErrNotFound = errors.New("resolver: DID document not found")
