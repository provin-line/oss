package mirrorstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/tlog"
)

// recordsFile is the per-log records journal: one JSON envelope per line
// (NDJSON), fsynced on every append. Its shape and fsync/replay-verify
// discipline mirror tlog/filelog.go's `entry` / `replay` / `Append` (source
// of truth for the on-disk format this package replicates independently —
// see the package doc for why it cannot import filelog's internals).
const recordsFile = "records.ndjson"

// journalEntry is the on-disk envelope for one record: field-for-field the
// same versioned shape as tlog/filelog.go's private `entry` type.
type journalEntry struct {
	V       int    `json:"v"`
	Index   uint64 `json:"index"`
	Payload []byte `json:"payload"`
	Hash    string `json:"hash"`
}

// ChainHash is the pinned hash-chain commitment: sha256( []byte(prevHex) ‖
// payload ), with the genesis record chaining from the EMPTY STRING (see
// tlog/tlog.go's Record.Hash doc). tlog/filelog and tlog/memlog each carry
// their own unexported copy of this exact formula; mirrorstore needs an
// independent copy for the same import-boundary reason, but EXPORTS it —
// Task 5's MirrorLogSegment handler recomputes the identical chain head
// with this function for D-T2 acceptance rule 1 ("the registry recomputes
// the hash chain from its stored tail through the segment and REQUIRES the
// recomputed head to equal checkpoint.head"), so the accept-time check and
// this store's own defense-in-depth re-check can never silently disagree
// about the formula.
func ChainHash(prev string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// marshalJournalEntry serializes one envelope line. Local storage bytes,
// never hashed or signed over as-is (ChainHash covers the payload directly;
// canonical form is not required here).
func marshalJournalEntry(e journalEntry) ([]byte, error) {
	// canonicalizer-hygiene-exempt: local storage envelope, not a signing scope.
	return json.Marshal(e)
}

// replayJournal reads and verifies path's whole chain, mirroring
// tlog/filelog.go's replay: every record's index must be dense from 0 and
// its hash must recompute from the running chain, or the journal is
// damaged. offsets[i] is the cumulative byte length of the file through
// (and including) record i — the truncation point a caller passes to
// truncateJournal to cut the file back to i+1 records without touching
// what came before. A missing file is an empty, undamaged log. torn
// reports a final line with no trailing newline (crash mid-append):
// keepBytes is the byte length of the last COMPLETE line — every complete
// line was fsynced, so an unterminated fragment is provably an
// uncommitted append (same doctrine as filelog's torn-tail handling).
func replayJournal(path string) (records []*tlog.Record, offsets []int64, torn bool, keepBytes int64, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, false, 0, nil
	}
	if err != nil {
		return nil, nil, false, 0, fmt.Errorf("mirrorstore: read %s: %w", path, err)
	}
	if n := len(raw); n > 0 && raw[n-1] != '\n' {
		cut := bytes.LastIndexByte(raw, '\n') + 1
		torn = true
		keepBytes = int64(cut)
		raw = raw[:cut]
	}
	prev := ""
	var pos int64
	line := 0
	for len(raw) > 0 {
		nl := bytes.IndexByte(raw, '\n')
		lineBytes := raw[:nl]
		raw = raw[nl+1:]
		pos += int64(nl) + 1
		line++
		var e journalEntry
		if derr := canon.NewStrictDecoder(lineBytes).Decode(&e); derr != nil {
			return nil, nil, false, 0, fmt.Errorf("mirrorstore: %s line %d: damaged entry: %w", path, line, derr)
		}
		if e.V != 1 {
			return nil, nil, false, 0, fmt.Errorf("mirrorstore: %s line %d: unsupported entry version %d", path, line, e.V)
		}
		if e.Index != uint64(line-1) {
			return nil, nil, false, 0, fmt.Errorf("mirrorstore: %s line %d: index %d breaks density", path, line, e.Index)
		}
		if got := ChainHash(prev, e.Payload); got != e.Hash {
			return nil, nil, false, 0, fmt.Errorf("mirrorstore: %s line %d: chain hash mismatch (tampered or truncated-and-regrown)", path, line)
		}
		records = append(records, &tlog.Record{Index: e.Index, Payload: e.Payload, Hash: e.Hash})
		offsets = append(offsets, pos)
		prev = e.Hash
	}
	return records, offsets, torn, keepBytes, nil
}

// appendJournal opens path for append, writes one envelope line per
// payload (continuing the chain from prevHash and startIndex), and fsyncs
// the file once after the whole batch — the same fsync-before-return
// discipline as tlog/filelog.go's Append, batched because a call here is
// one MirrorLogSegment request's worth of records (already bounded by
// D-T2's max-batch-records/max-batch-bytes caps), not one record at a
// time. Returns the new records on success.
func appendJournal(dir string, startIndex uint64, prevHash string, payloads [][]byte) ([]*tlog.Record, error) {
	path := filepath.Join(dir, recordsFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("mirrorstore: open %s for append: %w", path, err)
	}
	defer f.Close()
	recs := make([]*tlog.Record, 0, len(payloads))
	prev := prevHash
	for i, payload := range payloads {
		stored := make([]byte, len(payload))
		copy(stored, payload)
		rec := &tlog.Record{Index: startIndex + uint64(i), Payload: stored, Hash: ChainHash(prev, stored)}
		line, merr := marshalJournalEntry(journalEntry{V: 1, Index: rec.Index, Payload: stored, Hash: rec.Hash})
		if merr != nil {
			return nil, fmt.Errorf("mirrorstore: marshal entry %d: %w", rec.Index, merr)
		}
		if _, werr := f.Write(append(line, '\n')); werr != nil {
			return nil, fmt.Errorf("mirrorstore: append entry %d: %w", rec.Index, werr)
		}
		recs = append(recs, rec)
		prev = rec.Hash
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("mirrorstore: fsync %s: %w", path, err)
	}
	return recs, nil
}

// truncateJournal cuts the records journal under dir back to exactly size
// bytes (an offset replayJournal returned for the same file) and fsyncs
// the truncation — used both for torn-tail cleanup and for cutting unacked
// records back to the last verified checkpoint size on reopen (see
// openLogDir).
func truncateJournal(dir string, size int64) error {
	path := filepath.Join(dir, recordsFile)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mirrorstore: open %s for truncate: %w", path, err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return fmt.Errorf("mirrorstore: truncate %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("mirrorstore: fsync truncated %s: %w", path, err)
	}
	return fsyncDir(dir)
}

// journalSize returns the current byte length of the records journal under
// dir (0 if the file has never been created). AppendVerified reads this
// BEFORE appending new records so that, if the checkpoint write that must
// follow fails, it can roll the journal back to exactly this offset — the
// on-disk file must never hold records beyond what e.records/e.cp (the
// in-memory, publicly-visible state) claim.
func journalSize(dir string) (int64, error) {
	path := filepath.Join(dir, recordsFile)
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("mirrorstore: stat %s: %w", path, err)
	}
	return fi.Size(), nil
}
