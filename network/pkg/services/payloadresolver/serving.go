package payloadresolver

import (
	"context"
	"errors"
	"log/slog"
)

// AllowList is the serving-boundary admission seam: Admit returns nil when
// callerDID is admitted by pipelineDID's allow-list, a non-nil error otherwise.
// The package defines it here (dependency-inverted) so payloadresolver imports no
// chainmanager; *chainmanager.Service satisfies it via its exported Admit.
type AllowList interface {
	Admit(pipelineDID, callerDID string) error
}

// ServingBoundary authorizes a caller against a payload's owner set and, ONLY on
// admission, reads and returns the bytes. It is the authorize-before-read gate
// (F9): a not-admitted or absent request never triggers a payload read or hash
// (removing the pre-authorization amplification), and BOTH denial outcomes
// return the same ErrNotFound so the wire cannot distinguish "present but
// forbidden" from "absent" (closing the existence oracle, F4). The real reason
// is recorded server-side only.
//
// It is the serving policy layer over the pure content-addressed Service: the
// Service stores and reads bytes; the ServingBoundary decides WHO may read them.
// Admission (allow-list) is authorization, not cryptographic verification — the
// L2 wireauth proof is still verified by the handler before Serve is reached.
type ServingBoundary struct {
	svc    *Service
	allows AllowList
	logger *slog.Logger
}

// ServingOption configures a ServingBoundary.
type ServingOption func(*ServingBoundary)

// WithLogger sets the logger used for the server-side denial reason (default
// slog.Default()). Denials are logged at Debug — operationally traceable without
// turning an existence-probe flood into a log flood.
func WithLogger(l *slog.Logger) ServingOption {
	return func(b *ServingBoundary) {
		if l != nil {
			b.logger = l
		}
	}
}

// NewServingBoundary returns a ServingBoundary that serves payloads from svc to
// callers admitted by allows.
func NewServingBoundary(svc *Service, allows AllowList, opts ...ServingOption) *ServingBoundary {
	b := &ServingBoundary{svc: svc, allows: allows, logger: slog.Default()}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Serve returns the payload bytes held at hash iff callerDID is admitted by at
// least one of the payload's owners (any-owner-admits: a caller that may receive
// the bytes via one owner learns nothing extra from a bit-identical copy owned by
// a stricter pipeline). Authorization runs on owner metadata ALONE; the bytes are
// read and re-hashed only after admission succeeds.
//
// A not-admitted caller and an absent hash both return ErrNotFound — identical on
// the wire — so a caller who cannot receive the bytes cannot learn whether they
// exist. The real distinction (absent vs not-admitted) is logged server-side.
// A malformed hash, a context error, or a damaged/vanished store surface as their
// own (non-NotFound) errors: those are faults, not existence signals.
func (b *ServingBoundary) Serve(ctx context.Context, hash, callerDID string) ([]byte, error) {
	owners, err := b.svc.Owners(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			b.logger.DebugContext(ctx, "payload serve denied", "reason", "absent", "hash", hash, "caller", callerDID)
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !b.admittedByAnyOwner(owners, callerDID) {
		// Collapse to the same sentinel as an absent hash: the caller cannot tell
		// "exists but you are not admitted" from "does not exist".
		b.logger.DebugContext(ctx, "payload serve denied", "reason", "not_admitted", "hash", hash, "caller", callerDID)
		return nil, ErrNotFound
	}
	// Admitted: NOW read (and re-hash) the bytes.
	payload, _, err := b.svc.Resolve(ctx, hash)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (b *ServingBoundary) admittedByAnyOwner(owners []string, callerDID string) bool {
	for _, owner := range owners {
		if b.allows.Admit(owner, callerDID) == nil {
			return true
		}
	}
	return false
}
