package mirrorstore

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// Open opens (creating if needed) the mirror store rooted at root, one
// subdirectory per log. Every EXISTING log directory is replay-verified
// and reconciled here (reopen recovery, D-T4): records beyond the
// persisted checkpoint's Size are truncated (never acked, the shipper
// resumes and reships them); a journal shorter than the checkpoint size,
// or one whose recorded chain at the checkpoint's size does not match
// checkpoint.Head, is a damaged log. Open does not fail as a whole for
// that — a single mirrored log's damage must not deny service to every
// other log this registry custodies — but marks that one log POISONED:
// every subsequent AckedSize / Checkpoint / Get / AppendVerified call for
// it returns an error instead of silently reading a truncated or absent
// view.
func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("mirrorstore: create root %s: %w", root, err)
	}
	des, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("mirrorstore: list root %s: %w", root, err)
	}
	logs := make(map[string]*logEntry, len(des))
	for _, de := range des {
		if !de.IsDir() || !isDirNameShaped(de.Name()) {
			continue
		}
		dir := filepath.Join(root, de.Name())
		logs[de.Name()] = openLogDir(dir)
	}
	return &Store{root: root, logs: logs}, nil
}

// isDirNameShaped reports whether name looks like a dirName(logID) output
// (a lowercase hex sha256, 64 characters) — a defensive filter so a stray
// non-log entry under root is neither adopted as a log nor crashes Open;
// foreign entries are simply skipped, the same posture
// network/pkg/services/auditor/filestore's List/ListNewest take toward
// foreign filenames.
func isDirNameShaped(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// openLogDir replay-verifies and reconciles one log directory (see Open's
// doc). It never returns an error: damage is recorded on the returned
// logEntry as poisonErr instead, so one damaged log cannot fail Open for
// the whole store.
func openLogDir(dir string) *logEntry {
	records, offsets, torn, keepBytes, err := replayJournal(filepath.Join(dir, recordsFile))
	if err != nil {
		return &logEntry{dir: dir, poisonErr: fmt.Errorf("damaged records journal: %w", err)}
	}
	if torn {
		if err := truncateJournal(dir, keepBytes); err != nil {
			return &logEntry{dir: dir, poisonErr: fmt.Errorf("truncate torn tail: %w", err)}
		}
	}
	cp, err := readCheckpointFile(dir)
	if err != nil {
		return &logEntry{dir: dir, poisonErr: fmt.Errorf("damaged checkpoint: %w", err)}
	}
	var checkpointSize uint64
	checkpointHead := ""
	if cp != nil {
		checkpointSize = cp.Size
		checkpointHead = cp.Head
	}
	if checkpointSize > uint64(len(records)) {
		return &logEntry{dir: dir, poisonErr: fmt.Errorf(
			"journal has %d records, shorter than the checkpoint's size %d — never-acked records were lost",
			len(records), checkpointSize)}
	}
	expectedHead := ""
	if checkpointSize > 0 {
		expectedHead = records[checkpointSize-1].Hash
	}
	if expectedHead != checkpointHead {
		return &logEntry{dir: dir, poisonErr: fmt.Errorf(
			"chain mismatch: checkpoint head %q at size %d does not match the recorded chain (%q)",
			checkpointHead, checkpointSize, expectedHead)}
	}
	if uint64(len(records)) > checkpointSize {
		var offset int64
		if checkpointSize > 0 {
			offset = offsets[checkpointSize-1]
		}
		if err := truncateJournal(dir, offset); err != nil {
			return &logEntry{dir: dir, poisonErr: fmt.Errorf(
				"truncate unacked tail to checkpoint size %d: %w", checkpointSize, err)}
		}
		records = records[:checkpointSize]
	}
	return &logEntry{dir: dir, records: records, cp: cp}
}
