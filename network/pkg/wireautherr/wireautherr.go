// Package wireautherr is the single wireauth-sentinel → Connect status code
// classifier for every network handler that carries a wireauth.Proof. It
// exists to remove the drift risk of six independent copies of this mapping
// (one per handler): a shared classifier means the mapping can only get out
// of sync with the wireauth package's own sentinel taxonomy, not with itself.
//
// This package deliberately depends on both the transport-agnostic wireauth
// package and connectrpc.com/connect — that asymmetry is the point: wireauth
// itself MUST stay transport-agnostic (no connect-go import), so the
// transport-specific mapping lives here instead, one layer out.
package wireautherr

import (
	"errors"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// Code returns the Connect status code for a wireauth sentinel error err (as
// determined by errors.Is, so a wrapped sentinel classifies the same as the
// bare one) and true. If err is not a wireauth sentinel this package
// classifies, it returns (0, false); callers should fall through to their own
// domain-specific mapping in that case.
//
// The mapping:
//   - ErrMissingProof, ErrMalformedProof, ErrInvalidView (structural — the
//     proof shape itself is broken): CodeInvalidArgument.
//   - ErrResolverUnavailable, ErrBeforeEpoch (transient — the signer's
//     authenticity could not be evaluated, or the verifier is still inside
//     its restart-epoch boot window): CodeUnavailable, retryable. Neither is
//     an identity verdict.
//   - ErrExpired, ErrFromFuture, ErrKeyResolution, ErrSignatureInvalid,
//     ErrReplay (a definitive identity rejection): CodeUnauthenticated.
func Code(err error) (connect.Code, bool) {
	switch {
	case errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView):
		return connect.CodeInvalidArgument, true
	case errors.Is(err, wireauth.ErrResolverUnavailable),
		errors.Is(err, wireauth.ErrBeforeEpoch):
		return connect.CodeUnavailable, true
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.CodeUnauthenticated, true
	default:
		return 0, false
	}
}
