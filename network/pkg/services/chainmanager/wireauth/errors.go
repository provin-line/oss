// Package wireauth is the L2 peer-authentication layer of the chain manager:
// every internet-facing ChainPeerService RPC carries an Ed25519 Proof over a
// JCS-canonicalized per-RPC view, and this package signs and verifies them.
//
// It is the only authentication on the ChainPeerService surface (there is no L1
// JWT there), so the verification pipeline is fail-closed and ordered: cheap
// structural checks first, the DID-key resolution and signature check next, and
// the one state-mutating step (nonce record) strictly last and only after the
// signature verifies — a failed forgery must never burn a legitimate signer's
// nonce. All failures are typed sentinels so a handler maps each to a transport
// code via errors.Is without string-matching.
package wireauth

import "errors"

var (
	// ErrMissingProof is a structurally absent proof: empty signer DID, nonce,
	// or signature.
	ErrMissingProof = errors.New("wireauth: missing proof")
	// ErrMalformedProof is a present-but-ill-formed proof: a non-second-precision
	// or unparseable issuedAt, a bad nonce, or an empty op. Distinct from
	// ErrInvalidView (which is about the fields payload).
	ErrMalformedProof = errors.New("wireauth: malformed proof")
	// ErrInvalidView is a fields payload that violates the value grammar (only
	// string/bool/null and nested objects/arrays of those are allowed; numbers
	// must be carried as decimal strings).
	ErrInvalidView = errors.New("wireauth: invalid view")
	// ErrBeforeEpoch is a proof issued before this verifier's restart epoch (the
	// in-memory nonce store has no record of pre-restart nonces, so anything from
	// before the epoch is rejected rather than risk replay).
	ErrBeforeEpoch = errors.New("wireauth: proof issued before epoch")
	// ErrExpired is a proof whose issuedAt is older than the acceptance window
	// allows.
	ErrExpired = errors.New("wireauth: proof expired")
	// ErrFromFuture is a proof whose issuedAt is further ahead than the clock-skew
	// tolerance allows.
	ErrFromFuture = errors.New("wireauth: proof from the future")
	// ErrKeyResolution is a failure resolving the signer's #auth key (resolver
	// miss, key not under the authentication relationship, controller mismatch).
	// It is a DEFINITIVE identity failure (→ Unauthenticated), distinct from
	// ErrResolverUnavailable below.
	ErrKeyResolution = errors.New("wireauth: cannot resolve signer auth key")
	// ErrResolverUnavailable is a TRANSIENT resolver condition — a timeout,
	// cancellation, or the resolver refusing new work at capacity — while
	// resolving the signer's key. It is NOT an identity failure: the signer's
	// authenticity could not be evaluated at all, so a handler maps it to a
	// retryable code (Unavailable), never Unauthenticated (which would tell an
	// honest peer its identity was rejected).
	ErrResolverUnavailable = errors.New("wireauth: signer-key resolver unavailable")
	// ErrSignatureInvalid is a proof whose signature does not verify against the
	// resolved key over the rebuilt view.
	ErrSignatureInvalid = errors.New("wireauth: signature does not verify")
	// ErrReplay is a nonce this signer has already spent.
	ErrReplay = errors.New("wireauth: nonce replay")
)
