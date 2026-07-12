package commands

import (
	"context"
	"fmt"
	"io"

	"github.com/provin-line/oss/tlog/filelog"
)

// EvidenceRotate seals the relationship-evidence log at dir into a cold-archive
// segment and starts a fresh live log in place (see filelog.Log.Rotate). It is
// an OFFLINE operator action: the log's single-opener flock means the daemon
// must be stopped first, else open returns ErrLocked and this fails loudly.
//
// This rotates a relationship-evidence directory specifically; it is not a
// generic multi-log rotation surface. The archived segment stays independently
// replay-verifiable (and carries a signed checkpoint iff the log is armed with a
// signer); retention becomes "keep the archive for the audit horizon" rather
// than deleting records, so the tlog append-only contract is never violated.
func EvidenceRotate(ctx context.Context, out io.Writer, dir string) error {
	if dir == "" {
		return fmt.Errorf("evidence rotate: log directory is required")
	}
	l, err := filelog.New(dir)
	if err != nil {
		return fmt.Errorf("evidence rotate: open %s (is the daemon stopped?): %w", dir, err)
	}
	defer l.Close()
	rs, err := l.Rotate(ctx)
	if err != nil {
		return fmt.Errorf("evidence rotate: %w", err)
	}
	seal := "unsigned (storage rotation; integrity by chain replay + filesystem access control)"
	if rs.Checkpoint != nil {
		seal = "signed checkpoint by " + rs.Checkpoint.SignedBy
	}
	fmt.Fprintf(out, "rotated evidence log at %s\n", dir)
	fmt.Fprintf(out, "  segment:   %d\n", rs.Segment)
	fmt.Fprintf(out, "  records:   %d\n", rs.Size)
	fmt.Fprintf(out, "  head:      %s\n", rs.Head)
	fmt.Fprintf(out, "  archived:  %s\n", rs.Path)
	fmt.Fprintf(out, "  seal:      %s\n", seal)
	return nil
}
