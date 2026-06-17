package nats

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"
)

// DirPublisher is a production JWTPublisher that writes each signed account JWT to
// <dir>/<accountPub>.jwt — the unsharded file layout a nats-server directory
// account resolver (DirAccResolver) loads on first lookup. It imports only
// os/path/filepath/nkeys, so wiring it into the production graph does NOT pull in
// the nats-server (slice-14 D-n7 boundary).
//
// Scope (slice-15 D-m1): the directory store does NOT watch files, so this
// publisher gives first-lookup correctness for accounts looked up after the file
// exists; it does not live-update an account a client has already connected under.
// The live-propagation publisher ($SYS/Store/reload) is a sibling impl, deferred.
type DirPublisher struct {
	dir string
}

// NewDirPublisher returns a DirPublisher writing account JWTs under dir.
func NewDirPublisher(dir string) *DirPublisher { return &DirPublisher{dir: dir} }

var _ JWTPublisher = (*DirPublisher)(nil)

// Publish writes accountJWT to <dir>/<accountPub>.jwt atomically (temp file in the
// same directory + rename), so a concurrent resolver read never observes a
// half-written JWT. accountPub is validated as a NATS account public key before
// forming the path (no traversal / malformed filename).
func (p *DirPublisher) Publish(accountPub, accountJWT string) error {
	if !nkeys.IsValidPublicAccountKey(accountPub) {
		return fmt.Errorf("nats: invalid account public key %q", accountPub)
	}
	final := filepath.Join(p.dir, accountPub+".jwt")
	tmp, err := os.CreateTemp(p.dir, accountPub+".*.tmp")
	if err != nil {
		return fmt.Errorf("nats: create temp JWT file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we fail before the rename commits.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(accountJWT); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nats: write JWT: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nats: chmod JWT: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nats: close JWT: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("nats: commit JWT: %w", err)
	}
	committed = true
	return nil
}
