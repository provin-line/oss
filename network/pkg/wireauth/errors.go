// Package wireauth is the L2 peer-authentication layer of the network
// services: every RPC that takes an AuthProof (ChainPeerService's, and those
// of ChainService, AuditService, PayloadService, PayloadStoreService and
// TlogService that take one) carries an Ed25519 Proof over a
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

// Error is the type of this package's sentinel errors. The sentinels are
// constants, so no importer can reassign them. Compare an error with them by
// errors.Is only: the verifier and the nonce store wrap them with detail.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrMissingProof is a structurally absent proof: empty signer DID, nonce,
	// or signature.
	ErrMissingProof Error = "wireauth: missing proof"
	// ErrMalformedProof is a present-but-ill-formed proof: a non-second-precision
	// or unparseable issuedAt, a bad nonce, or an empty op. Distinct from
	// ErrInvalidView (which is about the fields payload).
	ErrMalformedProof Error = "wireauth: malformed proof"
	// ErrInvalidView is a fields payload that violates the value grammar (only
	// string/bool/null and nested objects/arrays of those are allowed; numbers
	// must be carried as decimal strings).
	ErrInvalidView Error = "wireauth: invalid view"
	// ErrBeforeEpoch is a proof issued before this verifier's restart epoch (the
	// in-memory nonce store has no record of pre-restart nonces, so anything from
	// before the epoch is rejected rather than risk replay).
	ErrBeforeEpoch Error = "wireauth: proof issued before epoch"
	// ErrExpired is a proof whose issuedAt is older than the acceptance window
	// allows.
	ErrExpired Error = "wireauth: proof expired"
	// ErrFromFuture is a proof whose issuedAt is further ahead than the clock-skew
	// tolerance allows.
	ErrFromFuture Error = "wireauth: proof from the future"
	// ErrKeyResolution is a failure resolving the signer's #auth key (resolver
	// miss, key not under the authentication relationship, controller mismatch,
	// an unusable key — did.ErrInvalidPublicKey).
	// It is a DEFINITIVE identity failure (→ Unauthenticated), distinct from
	// ErrResolverUnavailable below.
	ErrKeyResolution Error = "wireauth: cannot resolve signer auth key"
	// ErrResolverUnavailable is a TRANSIENT resolver condition — a timeout,
	// cancellation, or the resolver refusing new work at capacity — while
	// resolving the signer's key. It is NOT an identity failure: the signer's
	// authenticity could not be evaluated at all, so a handler maps it to a
	// retryable code (Unavailable), never Unauthenticated (which would tell an
	// honest peer its identity was rejected).
	ErrResolverUnavailable Error = "wireauth: signer-key resolver unavailable"
	// ErrSignatureInvalid is a proof whose signature does not verify against the
	// resolved key over the rebuilt view.
	ErrSignatureInvalid Error = "wireauth: signature does not verify"
	// ErrReplay is a nonce this signer has already spent.
	ErrReplay Error = "wireauth: nonce replay"
	// ErrWrongAudience is a proof that is not for this verifier: it names
	// another audience, or none (D-w12). It is checked with the structural
	// checks, before the signer is resolved, so such a proof spends no nonce.
	ErrWrongAudience Error = "wireauth: proof is for another audience"
	// ErrViewVersion is a proof of a view version this verifier does not
	// accept (VerifierConfig.AcceptedViewVersions), or of none. It is checked
	// with the structural checks, before the signer is resolved, so such a
	// proof spends no nonce.
	ErrViewVersion Error = "wireauth: proof of a view version this verifier does not accept"
)
