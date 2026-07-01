package auditor

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// ConsumeReason is the diagnostic outcome of a consume-locus verification (slice-17q),
// carried alongside the vc.ConfidenceState verdict as a notation — NOT a second wire enum.
type ConsumeReason string

const (
	ReasonVerified    ConsumeReason = "verified"    // full set fetched, root recomputes to the signed commitment
	ReasonMismatch    ConsumeReason = "mismatch"    // tamper, or the verifier disproved the supplied set (Failed)
	ReasonOrphan      ConsumeReason = "orphan"      // a supplied hash is authoritatively not found at the source
	ReasonUnavailable ConsumeReason = "unavailable" // a supplied hash could not be fetched (transient)
	ReasonIncomplete  ConsumeReason = "incomplete"  // full set fetched but it misses a claimed issuer (verifier Indeterminate)
)

// ErrInvalidConsumedHash is returned by Verify when a supplied consumed hash is not a
// "sha256:<64 hex>" content address — a CALLER precondition violation (the consumed set is
// the caller's input), fail-closed and distinct from a verdict: it will never resolve on
// retry, so it must not be misrouted to a transient Indeterminate. errors.Is-matchable.
var ErrInvalidConsumedHash = errors.New("auditor: invalid consumed hash")

// ErrSourceNotFound is the sentinel a SourceResolver returns (matched via errors.Is) when a
// content hash is AUTHORITATIVELY not resolvable (→ orphan). Any other non-context error is
// treated as transient (→ unavailable). This lets the verdict distinguish "the source does
// not exist" from "we could not reach it right now" — both Indeterminate, different reasons.
var ErrSourceNotFound = errors.New("auditor: source not found at resolver")

// SourceResolver fetches one source credential by content address for consume-locus
// verification (slice-17q). It is an AVAILABILITY seam, NOT a trust anchor: integrity comes
// from the credential's signature and vc.VerifySourceCommitment (fetch-location-independent),
// so a SourceResolver may fetch from any endpoint that holds the signed source (a production
// impl may fan out over the aggregate's DerivedFrom issuer endpoints, reusing the batch
// resolver's DID->#vc-resolver discovery, or fetch from the emitter). This seam isolates the
// deferred consumed-set discovery/transport policy — the verifier depends on the capability,
// not a wire contract (no new proto/RPC is frozen here, slice-17q D-17q-2/4).
type SourceResolver interface {
	Resolve(ctx context.Context, contentHash string) (*vc.PipelinePassCredential, error)
}

// ConsumeVerdict is a consume-locus verification result: the domain three-state plus a
// diagnostic reason. State maps onto the same vc.ConfidenceState the AuditRecord carries, so
// a recorded/served consume-locus verdict flows through the frozen 17i source_commitment
// field with no wire reshape.
type ConsumeVerdict struct {
	State    vc.ConfidenceState
	Reason   ConsumeReason
	Notation string
}

// ConsumeVerifier performs INDEPENDENT relying-party verification of an aggregate credential's
// source commitment (slice-17q): given the consumed content hashes, it fetches each source via
// a SourceResolver and recomputes the signed SourceRoot ITSELF — never trusting the emitter's
// self-reported verdict. Construct with NewConsumeVerifier.
type ConsumeVerifier struct {
	scv SourceCommitmentVerifier
	src SourceResolver
}

// NewConsumeVerifier validates its dependencies and returns a ready ConsumeVerifier.
func NewConsumeVerifier(scv SourceCommitmentVerifier, src SourceResolver) (*ConsumeVerifier, error) {
	if scv == nil || src == nil {
		return nil, ErrNilDependency
	}
	return &ConsumeVerifier{scv: scv, src: src}, nil
}

// Verify fetches the consumed sources and recomputes the aggregate's source commitment.
//
// It recomputes ONLY when the FULL supplied set fetched with no tamper — a partial set is
// never fed to VerifySourceCommitment (the slice-17o P1 discipline: a subset can spuriously
// match or mismatch). Outcomes:
//   - full fetch, no tamper -> VerifySourceCommitment result recorded VERBATIM (Verified /
//     Failed=mismatch / Indeterminate=incomplete);
//   - a fetched body's content hash != the requested hash (tamper) -> Failed/mismatch (short-circuit);
//   - any supplied hash unfetchable -> Indeterminate (orphan if authoritatively not-found,
//     else unavailable), no recompute;
//   - context cancellation -> abort: returns the ctx error and a ZERO verdict, so the caller
//     records NOTHING (matching the emit-locus runner discipline).
func (v *ConsumeVerifier) Verify(ctx context.Context, aggCred *vc.PipelinePassCredential, consumedHashes []string) (ConsumeVerdict, error) {
	// Precondition: every supplied hash is a well-formed content address. A malformed hash is a
	// caller/discovery data error (never resolves on retry), so fail closed with an error rather
	// than misrouting it to a transient Indeterminate (the runner's isContentAddress discipline).
	for _, h := range consumedHashes {
		if !isContentAddress(h) {
			return ConsumeVerdict{}, fmt.Errorf("%w: %q", ErrInvalidConsumedHash, h)
		}
	}
	sources := make([]*vc.PipelinePassCredential, 0, len(consumedHashes))
	for _, h := range consumedHashes {
		cred, err := v.src.Resolve(ctx, h)
		if err != nil {
			switch {
			case isCtxErr(err):
				return ConsumeVerdict{}, err // abort — record nothing, retry later
			case errors.Is(err, ErrSourceNotFound):
				return ConsumeVerdict{State: vc.ConfidenceIndeterminate, Reason: ReasonOrphan,
					Notation: "consume-locus: source " + truncateForNote(h) + " not found at resolver"}, nil
			default:
				return ConsumeVerdict{State: vc.ConfidenceIndeterminate, Reason: ReasonUnavailable,
					Notation: "consume-locus: source " + truncateForNote(h) + " unavailable: " + err.Error()}, nil
			}
		}
		// Tamper gate: the fetched body must content-address to the requested hash, else the
		// resolver returned something other than what was asked for.
		got, herr := cred.Hash()
		if herr != nil {
			// A fetched body we cannot content-address is a content-quality problem with what
			// the resolver returned (not a transient fetch failure) → fail-closed mismatch,
			// consistent with the tamper gate below.
			return ConsumeVerdict{State: vc.ConfidenceFailed, Reason: ReasonMismatch,
				Notation: "consume-locus: fetched source for " + truncateForNote(h) + " not hashable: " + herr.Error()}, nil
		}
		if got != h {
			return ConsumeVerdict{State: vc.ConfidenceFailed, Reason: ReasonMismatch,
				Notation: "consume-locus: fetched body hash " + truncateForNote(got) + " != requested " + truncateForNote(h)}, nil
		}
		sources = append(sources, cred)
	}

	// Full set fetched, no tamper. Honor a cancellation that arrived during the fetch loop
	// before spending the recompute (a resolver that ignores ctx would not have surfaced it).
	if err := ctx.Err(); err != nil {
		return ConsumeVerdict{}, err // abort — record nothing
	}
	// Recompute and record VerifySourceCommitment VERBATIM.
	state, err := v.scv.VerifySourceCommitment(ctx, aggCred, sources)
	if err != nil && isCtxErr(err) {
		return ConsumeVerdict{}, err // abort
	}
	switch state {
	case vc.ConfidenceVerified:
		return ConsumeVerdict{State: state, Reason: ReasonVerified,
			Notation: fmt.Sprintf("consume-locus: independently verified over %d fetched sources", len(sources))}, nil
	case vc.ConfidenceIndeterminate:
		return ConsumeVerdict{State: state, Reason: ReasonIncomplete,
			Notation: "consume-locus: fetched set does not cover every claimed issuer"}, nil
	default: // Failed: a positive disproof over the full set, or a non-ctx verifier error
		note := "consume-locus: supplied set contradicts the signed commitment"
		if err != nil {
			// A non-ctx verifier error (duplicate gathered source, no commitment on the head,
			// hashing failure) is not a cryptographic contradiction of the set — label it as a
			// verifier error, not a contradiction.
			note = "consume-locus: verifier error: " + err.Error()
		}
		return ConsumeVerdict{State: vc.ConfidenceFailed, Reason: ReasonMismatch, Notation: note}, nil
	}
}
