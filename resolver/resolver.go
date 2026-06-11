// Package resolver defines DID Document resolution. Implementations live in
// subpackages:
//
//   - local: in-memory store for tests and fixtures
//   - grpc:  ConnectRPC call to a registry's DIDService; validates that the
//     returned document ID equals the requested DID (registry-substitution
//     defense)
//   - multi: home-registry-first with fallback to additional registries on
//     connection errors ONLY — application errors (not-found, permission) are
//     authoritative and short-circuit, so fallback never masks a
//     configuration error on the negative path
package resolver

import (
	"context"

	"github.com/provin-line/oss/packages/did"
)

// Resolver resolves a DID string to its DID Document.
type Resolver interface {
	Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error)
}
