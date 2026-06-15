// Package resolver defines DID Document resolution. Implementations live in
// subpackages. Only local is implemented today; grpc and multi are planned —
// the entries below describe their intended contract, not present code:
//
//   - local: in-memory store for tests and fixtures (implemented)
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

	"github.com/provin-line/oss/did"
)

// Resolver resolves a DID string to its DID Document.
type Resolver interface {
	Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error)
}
