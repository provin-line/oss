//go:build unix

package filelog

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive, non-blocking advisory lock on f. A conflicting
// lock held by any OTHER open file description — another process, or another
// open of this same file — returns ErrLocked; the lock releases automatically
// when f is closed (including on a process crash, so there is no stale-lock
// reclaim problem). This is the single-opener guard: exactly one live Log may
// append to a directory at a time.
func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrLocked
	}
	if err != nil {
		return fmt.Errorf("filelog: flock: %w", err)
	}
	return nil
}
