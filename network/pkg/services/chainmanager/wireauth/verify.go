package wireauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/didresolver"
)

// isTransientResolverErr reports whether a signer-key resolution error is a
// transient condition (the signer's authenticity could not be evaluated)
// rather than a definitive identity failure: a context timeout/cancellation,
// or the production resolver refusing new work at capacity
// (didresolver.ErrResolverBusy). It keeps the retry/Unauthenticated
// distinction in one place; any resolver implementation whose transient
// failures surface as context errors is covered without coupling.
func isTransientResolverErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, didresolver.ErrResolverBusy)
}

// maxNonceLen caps an accepted nonce's length. A nonce is opaque to the
// verifier (it tracks it only for replay defense), but an unbounded one would
// let a peer grow the in-memory nonce store without limit; 256 bytes is far
// above NewNonce's 22-char output and any reasonable peer nonce.
const maxNonceLen = 256

// DIDResolver resolves a peer DID to its DID Document — the source of the
// signer's #auth key. Implementations may do network I/O (cross-registry
// resolution), so Resolve takes a context.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// Authorizer decides whether signerDID may act as the actor named in a
// verified RPC's fields (the per-op, signer-to-actor policy). It runs AFTER
// signature verification (so it only ever sees authenticated callers — no
// policy oracle), receives the resolved signer document (so an owner/controller
// rule needs no second resolution), and MUST be side-effect-free. fields is an
// immutable deep copy; mutating it cannot affect the verified signature.
type Authorizer func(signerDID string, signerDoc *did.DIDDocument, fields map[string]any) error

// AcceptanceWindow is the asymmetric clock-skew tolerance for a proof's
// issuedAt: the past tolerance (latency, retries, queued delivery) is larger
// than the future tolerance (a peer far ahead is suspicious).
type AcceptanceWindow struct {
	MaxPast   time.Duration
	MaxFuture time.Duration
}

// NonceRetention is how long a nonce must be retained for replay defense: the
// full reach of the window. A proof is acceptable until issuedAt+MaxPast, and
// issuedAt may be as late as now+MaxFuture, so a nonce recorded at first use
// could still be re-presented up to MaxPast+MaxFuture later. Past that it can
// never be re-admitted, so it is safe to evict (see memNonceStore).
func (w AcceptanceWindow) NonceRetention() time.Duration {
	return w.MaxPast + w.MaxFuture
}

// DefaultAcceptanceWindow is the window applied when VerifierConfig.Window is
// wholly unset. It is exported as the single authoritative source so the
// composition root can derive the nonce-store retention from the SAME value the
// verifier defaults to, preventing drift (see NewMemoryNonceStore).
func DefaultAcceptanceWindow() AcceptanceWindow {
	return AcceptanceWindow{MaxPast: 60 * time.Second, MaxFuture: 5 * time.Second}
}

// VerifierConfig configures a Verifier. Resolver, Crypto, and Nonces are
// required (NewVerifier errors if any is nil). Clock defaults to time.Now and
// Epoch to the first whole second at or after boot+MaxFuture — the restart
// replay barrier (see NewVerifier). Window defaults to {60s past, 5s future}
// ONLY when wholly unset (the zero AcceptanceWindow); a partially-set window is
// honored exactly, so MaxFuture:0 stays expressible.
// Negative window durations are rejected. Canonicalization is NOT configurable:
// the signed-view format is frozen to JCS (ViewVersion), and a verify-side canon
// the sign side did not honor would be a divergence hazard, not a feature.
type VerifierConfig struct {
	Resolver DIDResolver
	Crypto   crypto.Verifier
	Nonces   NonceStore
	Clock    func() time.Time
	Epoch    time.Time
	Window   AcceptanceWindow
}

// Verifier runs the ordered L2 verification pipeline over a Proof.
type Verifier struct {
	resolver DIDResolver
	crypto   crypto.Verifier
	nonces   NonceStore
	clock    func() time.Time
	epoch    time.Time
	window   AcceptanceWindow
}

// NewVerifier validates cfg and applies defaults. It errors rather than
// nil-panicking on the first internet request when a required dep is missing.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("wireauth: VerifierConfig.Resolver is required")
	}
	if cfg.Crypto == nil {
		return nil, fmt.Errorf("wireauth: VerifierConfig.Crypto is required")
	}
	if cfg.Nonces == nil {
		return nil, fmt.Errorf("wireauth: VerifierConfig.Nonces is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	// Resolve the window before the epoch: the default epoch is derived from the
	// effective MaxFuture. Default only when the window is wholly unset — a
	// partially-set window must be honored exactly, so MaxFuture:0 ("reject any
	// future-dated proof") stays expressible rather than being silently widened.
	window := cfg.Window
	if window == (AcceptanceWindow{}) {
		window = DefaultAcceptanceWindow()
	}
	if window.MaxPast < 0 || window.MaxFuture < 0 {
		return nil, fmt.Errorf("wireauth: VerifierConfig.Window durations must be non-negative")
	}
	epoch := cfg.Epoch
	if epoch.IsZero() {
		// Default epoch = the first whole second at or after boot+MaxFuture. This
		// closes the restart replay window fully (under a non-backward-stepping
		// clock): any proof acceptable before the restart had issuedAt below the
		// window's future bound (< boot+MaxFuture ≤ epoch), so it is rejected after
		// the in-memory nonce store resets. The cost is that a default-epoch
		// verifier rejects even legitimate current-time proofs for ~MaxFuture after
		// boot; peers recover by retrying. An explicit Epoch overrides this.
		epoch = ceilToSecond(clock().UTC().Add(window.MaxFuture))
	}
	return &Verifier{
		resolver: cfg.Resolver, crypto: cfg.Crypto, nonces: cfg.Nonces,
		clock: clock, epoch: epoch, window: window,
	}, nil
}

// Verify runs the ordered pipeline for one ChainPeerService RPC: cheap
// structural checks, then time bounds, then key resolution, signature
// verification, authorization, and — strictly last and only on success — the
// nonce record. A failed forgery never reaches the nonce step, so it cannot
// burn a legitimate signer's nonce.
//
// op is the RPC's view discriminator and fields its business object, both of
// which the caller reconstructs from the request being served (never from the
// proof). authorize may be nil to skip the signer-to-actor check.
func (v *Verifier) Verify(ctx context.Context, op string, fields map[string]any, proof Proof, authorize Authorizer) error {
	// 1. Structural / malformed checks (fail-fast, side-effect-free).
	if proof.SignerDID == "" || proof.Nonce == "" || len(proof.Signature) == 0 {
		return ErrMissingProof
	}
	if op == "" {
		return fmt.Errorf("%w: empty op", ErrMalformedProof)
	}
	if len(proof.Nonce) > maxNonceLen {
		return fmt.Errorf("%w: nonce exceeds %d bytes", ErrMalformedProof, maxNonceLen)
	}
	if proof.IssuedAt.Truncate(time.Second) != proof.IssuedAt {
		return fmt.Errorf("%w: issuedAt is not second-precision", ErrMalformedProof)
	}
	if err := validateFields(fields); err != nil {
		return err
	}

	// 2. Restart epoch barrier (before the window so its sentinel wins).
	if proof.IssuedAt.Before(v.epoch) {
		return fmt.Errorf("%w: issued %s, epoch %s", ErrBeforeEpoch, proof.IssuedAt.UTC().Format(time.RFC3339), v.epoch.UTC().Format(time.RFC3339))
	}

	// 3. Acceptance window (asymmetric).
	now := v.clock().UTC()
	if proof.IssuedAt.Before(now.Add(-v.window.MaxPast)) {
		return fmt.Errorf("%w: issued %s, now %s", ErrExpired, proof.IssuedAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if proof.IssuedAt.After(now.Add(v.window.MaxFuture)) {
		return fmt.Errorf("%w: issued %s, now %s", ErrFromFuture, proof.IssuedAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}

	// 4. Resolve the signer's #auth key.
	doc, err := v.resolver.Resolve(ctx, proof.SignerDID)
	if err != nil {
		// A transient resolver condition (timeout, cancellation, or capacity) is
		// not an identity failure — the signer's authenticity was never
		// evaluated. Surface it distinctly so the handler returns a retryable
		// code instead of Unauthenticated.
		if isTransientResolverErr(err) {
			return fmt.Errorf("%w: resolve %s: %w", ErrResolverUnavailable, proof.SignerDID, err)
		}
		return fmt.Errorf("%w: resolve %s: %v", ErrKeyResolution, proof.SignerDID, err)
	}
	pub, err := did.ExtractPublicKey(doc, proof.SignerDID+"#auth", did.RelationshipAuthentication)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyResolution, err)
	}

	// 5. Rebuild the canonical bytes through the same helper Sign used.
	msg, err := viewBytes(proof.SignerDID, op, proof.Nonce, proof.IssuedAt, fields)
	if err != nil {
		return err
	}

	// 6. Verify the signature.
	ok, err := v.crypto.Verify(pub, msg, proof.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	if !ok {
		return ErrSignatureInvalid
	}

	// 7. Authorize the now-authenticated signer over an immutable snapshot.
	if authorize != nil {
		if err := authorize(proof.SignerDID, doc, deepCopyFields(fields)); err != nil {
			return err
		}
	}

	// 8. Record the nonce — last, only on success (no-burn property).
	return v.nonces.Use(proof.SignerDID, proof.Nonce)
}

// ceilToSecond rounds t up to the next whole second unless it is already
// second-aligned. Ceiling the epoch keeps it at or above boot+MaxFuture, so the
// restart barrier stays fail-closed against second-precision proof timestamps
// (see NewVerifier for the replay-window rationale).
func ceilToSecond(t time.Time) time.Time {
	trunc := t.Truncate(time.Second)
	if trunc.Equal(t) {
		return trunc
	}
	return trunc.Add(time.Second)
}

// deepCopyFields returns an independent copy of a validated fields object so an
// Authorizer cannot mutate state observed elsewhere. It handles only the value
// grammar validateFields admits (string/bool/null + nested objects/arrays).
func deepCopyFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyFields(t)
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = deepCopyValue(e)
		}
		return cp
	default:
		return v // string, bool, nil — value types
	}
}
