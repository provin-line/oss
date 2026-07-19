package mirrorstore

import (
	"fmt"
	"os"
	"path/filepath"
)

// fsyncDir flushes a directory's entry table so a create/rename inside it
// survives a crash — the same idiom used throughout this repo's durable
// stores (tlog/filelog.go's fsyncDir, network/pkg/services/auditor/
// filestore.fsyncDir).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("mirrorstore: open dir %s for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("mirrorstore: fsync dir %s: %w", dir, err)
	}
	return nil
}

// afterRenameDirSync is the post-rename directory fsync writeAtomic performs
// to make the rename itself durable. It is a package var (not a direct call)
// ONLY so a white-box test can inject a post-rename dir-fsync failure — the
// one durability seam AppendVerified/AppendSegment must treat differently
// from a pre-rename failure (the rename already committed the new bytes, so
// rolling back by truncating the journal would leave the checkpoint AHEAD of
// the records). Production always binds it to fsyncDir.
var afterRenameDirSync = fsyncDir

// writeAtomic replaces path's contents with data: temp file in the same
// directory, write, fsync, close, rename, then fsync the directory so the
// rename itself is durable. Mirrors
// network/pkg/services/auditor/filestore.writeAtomic and tlog/filelog.go's
// writeFileSync/persistIntent — every durable store in this repo commits a
// file the same way.
//
// It reports renamed=true once os.Rename has SUCCEEDED, even if the
// subsequent directory fsync then fails: past that point path already names
// the new contents on disk (the rename is visible; only its crash-durability
// is uncertain), so the caller must NOT truncate-to-roll-back — see
// AppendVerified/AppendSegment's post-rename handling. A failure before the
// rename returns renamed=false and is safe to roll back.
func writeAtomic(path string, data []byte) (renamed bool, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return false, fmt.Errorf("mirrorstore: create temp for %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, fmt.Errorf("mirrorstore: write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, fmt.Errorf("mirrorstore: fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("mirrorstore: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("mirrorstore: rename into %s: %w", path, err)
	}
	if err := afterRenameDirSync(filepath.Dir(path)); err != nil {
		return true, fmt.Errorf("mirrorstore: fsync dir after rename into %s: %w", path, err)
	}
	return true, nil
}
