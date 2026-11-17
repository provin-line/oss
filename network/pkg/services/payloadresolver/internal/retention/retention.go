// Package retention decides whether a payload that arrives in parts is kept:
// its declared size must be neither zero nor above the quota, and its bytes
// must meet that size and have its declared content address. A Retention
// writes the bytes to a writer as they come, and commits the writer only
// when they do; otherwise it aborts it, so nothing is kept.
//
// This belongs to payloadresolver, which owns a payload's retention. It stays
// here, behind an internal path, until a PayloadWriter can be opened for an
// expected size and address and refuses, discarding them, the bytes that do
// not meet them. Then the checks of the bytes (Retention) move into that
// PayloadWriter, and the checks of the declaration (Declare) into Service,
// which already refuses an empty payload.
package retention

import (
	"errors"

	"github.com/provin-line/oss/contentaddress"
)

var (
	// ErrEmpty is a declared size of zero: an empty payload is never kept.
	ErrEmpty = errors.New("retention: the declared size is zero")
	// ErrOverQuota is a declared size above the quota.
	ErrOverQuota = errors.New("retention: the declared size is above the quota")
	// ErrOverrun is bytes beyond the declared size.
	ErrOverrun = errors.New("retention: the bytes exceed the declared size")
	// ErrShort is bytes that, once all have come, fall short of the declared
	// size.
	ErrShort = errors.New("retention: the bytes fall short of the declared size")
	// ErrAddressMismatch is bytes that are not the ones the declared content
	// address names.
	ErrAddressMismatch = errors.New("retention: the bytes are not the ones the declared content address names")
)

// Declaration is a declared size that Declare has accepted: neither zero nor
// above the quota. Outside this package only its zero value can be made, and
// a Retention keeps nothing for it (ErrEmpty).
type Declaration struct {
	size uint64
}

// Declare checks a declared size against the quota, before any byte comes,
// and returns the Declaration a Retention takes: ErrEmpty when the size is
// zero, ErrOverQuota when it is above quota, each with the zero Declaration.
func Declare(size, quota uint64) (Declaration, error) {
	if size == 0 {
		return Declaration{}, ErrEmpty
	}
	if size > quota {
		return Declaration{}, ErrOverQuota
	}
	return Declaration{size: size}, nil
}

// Writer is where a Retention writes the bytes, and what it commits or
// aborts. payloadresolver.PayloadWriter satisfies it.
type Writer interface {
	Write(p []byte) (int, error)
	Commit() (contentAddr string, err error)
	Abort() error
}

// Retention writes one payload's bytes to a Writer and commits them only when
// they meet the declared size and content address. After Write or Commit
// returns an error, or after Commit or Abort, the writer is finalized and the
// Retention is not used again; a payloadresolver.PayloadWriter answers a
// later Commit or Abort with ErrWriterFinalized.
type Retention struct {
	w        Writer
	size     uint64
	addr     contentaddress.Address
	received uint64
	seen     contentaddress.Hasher
}

// New returns a Retention writing to w the bytes of a payload of the size d
// declares, with content address addr.
func New(w Writer, d Declaration, addr contentaddress.Address) *Retention {
	return &Retention{w: w, size: d.size, addr: addr}
}

// Write writes p to the writer. Bytes beyond the declared size are
// ErrOverrun, and do not reach the writer. On ErrOverrun or the writer's own
// error, returned as it is, the writer is aborted.
func (r *Retention) Write(p []byte) error {
	if uint64(len(p)) > r.size-r.received {
		_ = r.w.Abort()
		return ErrOverrun
	}
	r.received += uint64(len(p))
	if _, err := r.w.Write(p); err != nil {
		_ = r.w.Abort()
		return err
	}
	r.seen.Write(p)
	return nil
}

// Commit commits the writer once the bytes meet the declared size and
// content address, and returns the address the writer kept them under, or
// its error as it is. The zero Declaration is ErrEmpty, bytes short of the
// size are ErrShort, and bytes that are not the ones the address names are
// ErrAddressMismatch: then the writer is aborted, and nothing is kept.
func (r *Retention) Commit() (string, error) {
	if r.size == 0 {
		_ = r.w.Abort()
		return "", ErrEmpty
	}
	if r.received != r.size {
		_ = r.w.Abort()
		return "", ErrShort
	}
	if r.seen.Address() != r.addr {
		_ = r.w.Abort()
		return "", ErrAddressMismatch
	}
	return r.w.Commit()
}

// Abort aborts the writer, for a stream that fails other than by its bytes,
// and returns the writer's error.
func (r *Retention) Abort() error {
	return r.w.Abort()
}
