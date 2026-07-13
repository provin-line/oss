//go:build !unix

package merklelog

import (
	"fmt"
	"os"
)

// lockFile is unsupported off Unix. merklelog already depends on directory fsync
// (fsyncDir) and advisory flock, both Unix facilities, so the durable log is
// Unix-targeted in practice; this stub keeps a GOOS=windows cross-compile
// honest by failing loudly rather than silently skipping the single-opener
// guard.
func lockFile(*os.File) error {
	return fmt.Errorf("merklelog: advisory file locking is not supported on this platform")
}
