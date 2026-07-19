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

// writeAtomic replaces path's contents with data: temp file in the same
// directory, write, fsync, close, rename, then fsync the directory so the
// rename itself is durable. Mirrors
// network/pkg/services/auditor/filestore.writeAtomic and tlog/filelog.go's
// writeFileSync/persistIntent — every durable store in this repo commits a
// file the same way.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("mirrorstore: create temp for %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("mirrorstore: write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("mirrorstore: fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("mirrorstore: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("mirrorstore: rename into %s: %w", path, err)
	}
	return fsyncDir(filepath.Dir(path))
}
