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
//
// # Ownership
//
// Store implementations (filestore, memstore) assume single-process ownership
// of their directory/state (no cross-process file lock) — same posture as the
// auditor's filestore. A PayloadWriter additionally assumes a single-goroutine
// caller: see PayloadWriter's doc.
package payloadresolver

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/provin-line/oss/vc"
)

// ErrInvalidArgument is a malformed content-address hash or a missing required
// argument. The handler maps it to InvalidArgument; ErrNotFound maps to
// NotFound.
var ErrInvalidArgument = errors.New("payloadresolver: invalid argument")

// ErrNotFound is a well-formed content address the store does not hold.
var ErrNotFound = errors.New("payloadresolver: payload not found")

// ErrWriterFinalized is returned by Write after Commit or Abort, and by a
// second call to Commit or Abort: a PayloadWriter is single-use past its first
// finalization. Both store backends return this exact sentinel so a caller
// (e.g. a client-streaming handler) can branch on it regardless of backend.
var ErrWriterFinalized = errors.New("payloadresolver: payload writer already committed or aborted")

// Store persists by-reference payloads by content address, together with the
// set of pipeline DIDs that emitted each payload.
type Store interface {
	// Put stores payload at its (store-recomputed) content address and records
	// ownerDID as an emitter of it. Idempotent on both the bytes
	// (content-addressed) and a repeat owner; a new owner is appended to the
	// address's owner set. Returns the recomputed content address.
	Put(payload []byte, ownerDID string) (string, error)
	// StoreWriter returns a streaming retain handle for ownerDID: the caller
	// writes payload bytes incrementally (io.Copy-compatible) instead of
	// buffering the whole payload before calling Put, then finalizes with
	// Commit or Abort. The content address is derived incrementally as bytes
	// are written, byte-identical to what Put would derive for the same bytes.
	//
	// ctx gates CREATION ONLY: it is checked once, here, and rejects a call
	// made with an already-cancelled/expired ctx. It is NOT retained or
	// consulted again afterward — the returned PayloadWriter outlives ctx and
	// is never itself cancelled by it. A caller that must abandon an
	// in-progress write on cancellation (or any other mid-stream failure,
	// e.g. a client-streaming handler whose caller hangs up) is responsible
	// for detecting that itself and calling Abort.
	StoreWriter(ctx context.Context, ownerDID string) (PayloadWriter, error)
	// Owners returns the owner set recorded at hash WITHOUT reading (or hashing)
	// the payload bytes — the cheap authorization basis the serving boundary
	// consults before it commits to serving (see ServingBoundary.Serve). Returns
	// ErrNotFound iff no entry exists at hash. A present entry with an
	// absent/unreadable owner sidecar returns an empty set (fail-closed at the
	// serving boundary: no owner admits), never ErrNotFound.
	Owners(hash string) (owners []string, err error)
	// Get returns the payload bytes and the owner set held at hash, or
	// ErrNotFound. A stored payload whose bytes no longer hash to the key is a
	// damaged entry (a distinct error), never a silent miss.
	Get(hash string) (payload []byte, owners []string, err error)
}

// PayloadWriter is a streaming retain handle returned by Store.StoreWriter.
// Callers write payload bytes incrementally, then finalize with EXACTLY ONE
// of Commit or Abort — a PayloadWriter is single-use.
//
// Like io.Writer generally, a PayloadWriter has a single-goroutine caller
// contract: Write/Commit/Abort are not safe to call concurrently on the same
// instance (neither implementation synchronizes its own internal state
// against concurrent use — only the underlying Store's cross-writer state is
// mutex-guarded). A client-streaming handler drives one PayloadWriter
// sequentially from its own receive loop, never fanning calls out across
// goroutines.
type PayloadWriter interface {
	io.Writer
	// Commit finalizes the write, deriving the content address from the bytes
	// written so far and persisting the payload durably under it (recording
	// ownerDID as an emitter, exactly as Put would). Returns ErrWriterFinalized
	// if the writer was already Committed or Aborted.
	Commit() (contentAddr string, err error)
	// Abort discards the writer's buffered/temp state: nothing written to it is
	// persisted. Returns ErrWriterFinalized if the writer was already Committed
	// or Aborted.
	Abort() error
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

// Owners returns the owner set recorded at hash WITHOUT reading the payload
// bytes — the cheap authorization basis a serving boundary consults before it
// commits to reading and streaming. The hash must be a well-formed content
// address (ErrInvalidArgument otherwise); a well-formed miss is ErrNotFound.
func (s *Service) Owners(ctx context.Context, hash string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !vc.IsContentAddress(hash) {
		return nil, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	return s.store.Owners(hash)
}

// Resolve returns the payload bytes and owner set held at hash. The hash must be
// a well-formed content address (ErrInvalidArgument otherwise); a well-formed
// miss is ErrNotFound.
//
// Resolve reads AND hashes the bytes, so a serving boundary must authorize the
// caller (via Owners) BEFORE calling it — see ServingBoundary.Serve.
func (s *Service) Resolve(ctx context.Context, hash string) ([]byte, []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !vc.IsContentAddress(hash) {
		return nil, nil, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	return s.store.Get(hash)
}
