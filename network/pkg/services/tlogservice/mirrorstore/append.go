package mirrorstore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/provin-line/oss/tlog"
)

// AppendVerified durably extends the mirror for logID with records — a
// segment the CALLER (the MirrorLogSegment handler, Task 5) has already
// verified for signature, caller identity, and from_index alignment
// against GetMirrorState.acked_size (D-T2 rules 1-3, 6). AppendVerified
// re-enforces, as defense in depth, every rule the store itself is able to
// check from its own state:
//
//   - exact-extend: cp.Size must equal the current acked size plus
//     len(records) — no ahead-checkpoints, no gaps (D-T2 rule 1/2 restated
//     at the storage layer). A request that does not fit this arithmetic
//     was never a fresh exact-extend; the handler is expected to have
//     already resolved any overlap/replay before calling here — see the
//     package doc's "Byte-identical replay" paragraph.
//   - the recomputed chain head (continuing from the stored tail through
//     records, via ChainHash) must equal cp.Head (D-T2 rule 1).
//   - cp.Origin must equal logID (mirrors
//     tlogservice.Service.Checkpoint's existing origin-agreement check for
//     local logs — a checkpoint signed for a DIFFERENT log id must never
//     be filed under this one).
//   - cp must actually be signed (non-empty SignedBy/Signature): this
//     store persists the REMOTE loop-signed checkpoint verbatim and never
//     synthesizes one, so an empty-signature value reaching here is a
//     caller bug, not evidence.
//   - checkpoint monotonicity: a cp.Size below the current acked size is a
//     STALE checkpoint. If the chain already recorded at cp.Size still
//     matches cp.Head, it is valid-but-outdated and is IGNORED — the call
//     returns the store's current (unregressed) acked size, a no-op
//     success (D-T2 rule 4). If it does not match, that is a genuine
//     conflict (two different signed heads claim the same size) and the
//     call fails loudly.
//   - the zero-new-records, equal-size-equal-head case (a checkpoint
//     resend with nothing to append — e.g. a lost-ack retry of the exact
//     prior call, or a loop's periodic re-checkpoint with no new records)
//     is an idempotent no-op: nothing is written.
//
// Crash ordering AND live-process ordering: new records are appended and
// fsynced to the journal BEFORE the checkpoint file is atomically
// replaced, but nothing OBSERVABLE (e.records, e.cp, or even this log's
// entry in the store's map for a log seen for the first time) changes
// until the checkpoint write itself has succeeded. A reader must never see
// records that no durable, signed checkpoint yet commits — that would
// happen if e.records advanced before writeCheckpointFile returned and
// writeCheckpointFile then failed (EIO, disk full): the live process would
// serve an acked size no persisted checkpoint backs, and a shipper cursor
// (GetMirrorState.acked_size) would advance past records the registry
// cannot actually prove. So the write path only stages: it computes the
// new records and the checkpoint bytes, durably applies both to disk, and
// mutates the in-memory state (and the map, for a brand-new log) only
// after that succeeds.
//
// If the records fsync succeeds but the checkpoint write then fails, the
// journal now holds bytes beyond what any durable checkpoint — and hence
// e.records — will claim; left alone, a later retry of the same segment
// would re-append the same index range and break the journal's density
// invariant. So a failed checkpoint write is followed by an immediate
// rollback: the journal is truncated back to its pre-append size (the
// same operation Open performs for a crash left in this exact state — see
// openLogDir). If that rollback ALSO fails, the disk and the in-memory
// view can no longer be reconciled at runtime, and the log is marked
// POISONED (mirrors tlog/filelog.go's rollback-failure poisoning) rather
// than left to silently diverge.
//
// Returns the store's acked size for logID after the call (unchanged for a
// no-op or a failure).
func (s *Store) AppendVerified(logID string, records [][]byte, cp *tlog.Checkpoint) (uint64, error) {
	if cp == nil {
		return 0, fmt.Errorf("mirrorstore: append %q: nil checkpoint", logID)
	}
	if cp.Origin != logID {
		return 0, fmt.Errorf("mirrorstore: append %q: checkpoint origin %q does not match the log id", logID, cp.Origin)
	}
	if cp.SignedBy == "" || len(cp.Signature) == 0 {
		return 0, fmt.Errorf("mirrorstore: append %q: checkpoint carries no signature — the registry never synthesizes one", logID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A read-only lookup — deliberately does NOT insert a fresh map entry
	// for a log id this store has never seen, even though one would be
	// convenient to build below: every check that can still reject the
	// request runs BEFORE any entry (or directory) is created, so a
	// malformed request against an unknown log id leaves no trace in
	// s.logs. The map only gains an entry once a call actually commits (or
	// is left poisoned after a rollback failure — see below).
	key := dirName(logID)
	e, existed := s.logs[key]
	if existed && e.poisonErr != nil {
		return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, e.poisonErr)
	}

	dir := filepath.Join(s.root, key)
	var currentRecords []*tlog.Record
	var currentCP *tlog.Checkpoint
	if existed {
		dir = e.dir
		currentRecords = e.records
		currentCP = e.cp
	}
	currentAcked := uint64(len(currentRecords))
	tail := ""
	if currentAcked > 0 {
		tail = currentRecords[currentAcked-1].Hash
	}

	if cp.Size < currentAcked {
		// Stale checkpoint. A non-empty records slice alongside a
		// regressing cp.Size is not a replay of anything the handler
		// should ever construct — reject rather than guess.
		if len(records) != 0 {
			return 0, fmt.Errorf("mirrorstore: append %q: checkpoint size %d is below the acked size %d but carries %d new records — malformed segment",
				logID, cp.Size, currentAcked, len(records))
		}
		expectedHead := ""
		if cp.Size > 0 {
			expectedHead = currentRecords[cp.Size-1].Hash
		}
		if expectedHead != cp.Head {
			return 0, fmt.Errorf("mirrorstore: append %q: stale checkpoint at size %d conflicts with the recorded chain (head %q, checkpoint claims %q)",
				logID, cp.Size, expectedHead, cp.Head)
		}
		return currentAcked, nil // valid but stale — ignored, never regresses the head
	}

	if cp.Size != currentAcked+uint64(len(records)) {
		return 0, fmt.Errorf("mirrorstore: append %q: checkpoint size %d != acked size %d + %d new records — not an exact extend",
			logID, cp.Size, currentAcked, len(records))
	}

	head := tail
	for _, payload := range records {
		head = ChainHash(head, payload)
	}
	if head != cp.Head {
		return 0, fmt.Errorf("mirrorstore: append %q: recomputed chain head %q != checkpoint head %q", logID, head, cp.Head)
	}

	if len(records) == 0 && currentCP != nil {
		return currentAcked, nil // idempotent no-op: nothing new, already checkpointed
	}

	// Every structural check above is now satisfied. Create the directory
	// only the FIRST time this store touches the log (existed==false
	// implies, by construction, that no prior call or Open scan ever
	// created it) — a log already in the map has a directory that is
	// already durably created, so re-running MkdirAll + the two fsyncs on
	// every append would be pure overhead on the hot path.
	if !existed {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, fmt.Errorf("mirrorstore: append %q: create log dir: %w", logID, err)
		}
		if err := fsyncDir(dir); err != nil {
			return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, err)
		}
		if err := fsyncDir(s.root); err != nil {
			return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, err)
		}
	}

	preSize, err := journalSize(dir)
	if err != nil {
		return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, err)
	}

	var newRecs []*tlog.Record
	if len(records) > 0 {
		nr, err := appendJournal(dir, currentAcked, tail, records)
		if err != nil {
			return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, err)
		}
		newRecs = nr
	}

	if err := writeCheckpointFile(dir, cp); err != nil {
		if len(newRecs) == 0 {
			// Nothing was appended to the journal this call — no rollback
			// needed, and no in-memory state has changed.
			return 0, fmt.Errorf("mirrorstore: append %q: write checkpoint: %w", logID, err)
		}
		if rerr := truncateJournal(dir, preSize); rerr != nil {
			poisonErr := fmt.Errorf("checkpoint write failed and the rollback truncate also failed: checkpoint error: %v; truncate error: %w", err, rerr)
			if existed {
				e.poisonErr = poisonErr
			} else {
				s.logs[key] = &logEntry{dir: dir, poisonErr: poisonErr}
			}
			return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, poisonErr)
		}
		return 0, fmt.Errorf("mirrorstore: append %q: write checkpoint: %w", logID, err)
	}

	if !existed {
		e = &logEntry{dir: dir}
		s.logs[key] = e
	}
	if len(newRecs) > 0 {
		e.records = append(currentRecords, newRecs...)
	} else {
		e.records = currentRecords
	}
	e.cp = cloneCheckpoint(cp)
	return uint64(len(e.records)), nil
}
