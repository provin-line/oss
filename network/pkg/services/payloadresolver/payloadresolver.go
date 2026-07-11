// Package payloadresolver is the publisher's serving-boundary domain for
// by-reference payload delivery: it retains the payload bytes a producing
// process emitted (keyed by their content address) together with the set of
// pipeline DIDs that emitted them, and serves them back by content address.
//
// It is the data-plane sibling of vcresolver: that service stores and serves
// provenance VCs; this one stores and serves the DATA a process transformed.
// The bytes carry no trust — a consumer re-hashes them against the credential's
// declared outputHash (the binding gate), so this domain never verifies, only
// content-addresses.
//
// # Owner set
//
// Content-addressing means two pipelines can legitimately emit identical bytes
// (same hash). The store therefore keeps a SET of owner pipeline DIDs per
// address, appended on each retain. The serving boundary admits a caller if
// ANY owner's allow-list admits it (payloadresolver/handler): a caller that may
// receive the bytes via one owner learns nothing extra from a bit-identical
// copy owned by another.
package payloadresolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// ErrInvalidArgument is a malformed content-address hash or a missing required
// argument. The handler maps it to InvalidArgument; ErrNotFound maps to
// NotFound.
var ErrInvalidArgument = errors.New("payloadresolver: invalid argument")

// ErrNotFound is a well-formed content address the store does not hold.
var ErrNotFound = errors.New("payloadresolver: payload not found")

// Store persists by-reference payloads by content address, together with the
// set of pipeline DIDs that emitted each payload.
type Store interface {
	// Put stores payload at its (store-recomputed) content address and records
	// ownerDID as an emitter of it. Idempotent on both the bytes
	// (content-addressed) and a repeat owner; a new owner is appended to the
	// address's owner set. Returns the recomputed content address.
	Put(payload []byte, ownerDID string) (string, error)
	// Get returns the payload bytes and the owner set held at hash, or
	// ErrNotFound. A stored payload whose bytes no longer hash to the key is a
	// damaged entry (a distinct error), never a silent miss.
	Get(hash string) (payload []byte, owners []string, err error)
}

// Service retains and serves by-reference payloads over a Store.
type Service struct {
	store Store
}

// New returns a Service over store.
func New(store Store) *Service {
	return &Service{store: store}
}

// Store records payload as emitted by ownerDID and returns its content address.
// The address is recomputed from the bytes by the store — never caller-supplied.
//
// Fail-closed inputs: an empty ownerDID is rejected (a payload with no owner
// could never be admitted for serving — no allow-list to match — so it would be
// a serve-deny orphan by construction), and empty bytes are rejected (a
// producing process never emits an empty payload; an empty by-reference payload
// could never bind).
func (s *Service) Store(ctx context.Context, payload []byte, ownerDID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if ownerDID == "" {
		return "", fmt.Errorf("%w: ownerDID must be non-empty", ErrInvalidArgument)
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("%w: payload must be non-empty", ErrInvalidArgument)
	}
	return s.store.Put(payload, ownerDID)
}

// Resolve returns the payload bytes and owner set held at hash. The hash must be
// a well-formed content address (ErrInvalidArgument otherwise); a well-formed
// miss is ErrNotFound.
func (s *Service) Resolve(ctx context.Context, hash string) ([]byte, []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !vc.IsContentAddress(hash) {
		return nil, nil, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	return s.store.Get(hash)
}
