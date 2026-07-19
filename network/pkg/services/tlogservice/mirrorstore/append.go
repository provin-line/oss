package mirrorstore

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/provin-line/oss/tlog"
)

// appendJournalFn is the journal-append step AppendVerified/AppendSegment
// perform. It is a package var (not a direct call) ONLY so a white-box test
// can inject a partial-write / fsync failure: a failed appendJournal may have
// left uncheckpointed bytes on disk, so the write path must roll the journal
// back to its pre-append size (or poison) exactly as it does for a failed
// checkpoint write. Production always binds it to appendJournal.
var appendJournalFn = appendJournal

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
//     package doc's "Byte-identical replay" paragraph. (The race-free
//     resolution of overlap/replay/gap lives in AppendSegment below, which
//     the Service now calls; AppendVerified stays the exact-extend +
//     monotonicity entry point the store's own tests exercise directly.)
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
// Rollback / poisoning on a failed durable step:
//
//   - if appendJournal fails (a partial os.File.Write or a Sync error), the
//     journal may now hold bytes beyond preSize that no checkpoint will
//     claim; left alone, a later retry of the same segment would re-append
//     the same index range and break the journal's density invariant on
//     reopen. So the journal is truncated back to its pre-append size.
//   - if the records fsync succeeds but the checkpoint write then fails
//     BEFORE its rename (marshal, temp create/write/fsync/close, or the
//     rename itself), the same truncate-to-preSize rollback applies: no
//     durable checkpoint names the new records, so they are removed.
//   - if the checkpoint write fails AFTER its rename (only the trailing
//     dir-fsync failed — writeCheckpointFile reports renamed=true), the
//     checkpoint file ALREADY names the new size. Truncating the journal
//     back to preSize would leave the checkpoint AHEAD of the records —
//     poisoned-inconsistent on the next Open. So this case does NOT
//     truncate: the journal keeps the appended records (they matched the
//     now-committed checkpoint), and the log is marked POISONED for the
//     rest of this process (its durability is genuinely uncertain). A fresh
//     Open reconciles from disk — records and checkpoint at the same size
//     if the rename survived, or records-ahead-of-checkpoint truncated back
//     to the checkpoint if a crash lost it; either way, never
//     checkpoint-ahead-of-records.
//   - if a truncate rollback ITSELF fails, the disk and the in-memory view
//     can no longer be reconciled at runtime, and the log is marked
//     POISONED (mirrors tlog/filelog.go's rollback-failure poisoning)
//     rather than left to silently diverge.
//
// Returns the store's acked size for logID after the call (unchanged for a
// no-op or a failure).
func (s *Store) AppendVerified(logID string, records [][]byte, cp *tlog.Checkpoint) (uint64, error) {
	if err := validateCheckpoint(logID, cp); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(logID, nil, records, cp)
}

// AppendSegment atomically resolves one MirrorLogSegment against the store's
// current acked size UNDER THE SAME LOCK the durable append holds, so a
// concurrent identical retry can never observe a torn intermediate size
// (D-T2 rule 2). It is the entry point tlogservice.Service.MirrorSegment
// calls; the fromIndex the caller has verified structurally (overflow,
// cp.Size == fromIndex + len) is resolved here against the live acked size:
//
//   - fromIndex == acked: exact extend (append + checkpoint durably).
//   - fromIndex < acked, records byte-identical to the stored overlap, and
//     fromIndex+len <= acked: a byte-identical replay of an already-acked
//     segment — a no-op success returning the unchanged acked size.
//   - fromIndex < acked with a byte mismatch, or fromIndex+len > acked (a
//     partial overlap): ErrConflict.
//   - fromIndex > acked (a gap): ErrConflict.
//
// Moving this resolution inside the lock is what closes the concurrency
// hole: with the acked read and the append split across two calls, two
// overlapping identical requests could both read the same acked size, the
// first commit as an extend, and the second then fail the exact-extend
// arithmetic with a plain error (mapped to Internal) instead of the replay
// no-op success D-T2 rule 2 requires.
func (s *Store) AppendSegment(logID string, fromIndex uint64, records [][]byte, cp *tlog.Checkpoint) (uint64, error) {
	if err := validateCheckpoint(logID, cp); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(logID, &fromIndex, records, cp)
}

// validateCheckpoint runs the checkpoint pre-checks that need no lock (nil,
// origin agreement, presence of a signature) — shared by AppendVerified and
// AppendSegment so both reject the same malformed inputs identically.
func validateCheckpoint(logID string, cp *tlog.Checkpoint) error {
	if cp == nil {
		return fmt.Errorf("mirrorstore: append %q: nil checkpoint", logID)
	}
	if cp.Origin != logID {
		return fmt.Errorf("mirrorstore: append %q: checkpoint origin %q does not match the log id", logID, cp.Origin)
	}
	if cp.SignedBy == "" || len(cp.Signature) == 0 {
		return fmt.Errorf("mirrorstore: append %q: checkpoint carries no signature — the registry never synthesizes one", logID)
	}
	return nil
}

// appendLocked is the shared body of AppendVerified (fromIndex == nil, the
// exact-extend + monotonicity path) and AppendSegment (fromIndex != nil, the
// atomic from_index resolution). The caller holds s.mu. Both paths converge
// on ONE durable exact-extend implementation below the branch, so the
// rollback / poisoning discipline (P1-C, P2-F) lives in a single place.
func (s *Store) appendLocked(logID string, fromIndex *uint64, records [][]byte, cp *tlog.Checkpoint) (uint64, error) {
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

	if fromIndex != nil {
		// --- Atomic segment resolution (D-T2 rule 2). Race-free: the acked
		// size is read here, under the same lock the append below holds.
		switch {
		case *fromIndex > currentAcked:
			return 0, fmt.Errorf("%w: append %q: from_index %d is ahead of the acked size %d (a gap)",
				ErrConflict, logID, *fromIndex, currentAcked)
		case *fromIndex < currentAcked:
			total := *fromIndex + uint64(len(records))
			if total < *fromIndex {
				return 0, fmt.Errorf("mirrorstore: append %q: from_index %d + %d records overflows uint64",
					logID, *fromIndex, len(records))
			}
			if total > currentAcked {
				return 0, fmt.Errorf("%w: append %q: replay range [%d,%d) extends past the acked size %d (partial overlap)",
					ErrConflict, logID, *fromIndex, total, currentAcked)
			}
			for i, payload := range records {
				if !bytes.Equal(currentRecords[*fromIndex+uint64(i)].Payload, payload) {
					return 0, fmt.Errorf("%w: append %q: record at index %d does not byte-match the already-mirrored record (partial overlap)",
						ErrConflict, logID, *fromIndex+uint64(i))
				}
			}
			return currentAcked, nil // byte-identical replay — no-op success
		}
		// *fromIndex == currentAcked: exact extend. Re-verify the checkpoint
		// arithmetic the caller already checked (defense in depth).
		if cp.Size != currentAcked+uint64(len(records)) {
			return 0, fmt.Errorf("%w: append %q: checkpoint size %d != acked size %d + %d new records — not an exact extend",
				ErrConflict, logID, cp.Size, currentAcked, len(records))
		}
	} else {
		// --- AppendVerified path: monotonicity + exact-extend, unchanged.
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
	}

	// --- Shared exact-extend durable body (both paths converge here with
	// records to append at currentAcked).
	head := tail
	for _, payload := range records {
		head = ChainHash(head, payload)
	}
	if head != cp.Head {
		return 0, fmt.Errorf("%w: append %q: recomputed chain head %q != checkpoint head %q", ErrConflict, logID, head, cp.Head)
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
		nr, aerr := appendJournalFn(dir, currentAcked, tail, records)
		if aerr != nil {
			// The journal may hold a partial/uncheckpointed tail beyond
			// preSize — roll it back so a later retry does not re-append
			// duplicate indexes (poison if the rollback itself fails).
			if rerr := truncateJournal(dir, preSize); rerr != nil {
				return 0, s.poison(key, dir, e, existed, logID, fmt.Errorf(
					"journal append failed and the rollback truncate also failed: append error: %v; truncate error: %w", aerr, rerr))
			}
			return 0, fmt.Errorf("mirrorstore: append %q: %w", logID, aerr)
		}
		newRecs = nr
	}

	renamed, werr := writeCheckpointFile(dir, cp)
	if werr != nil {
		if len(newRecs) == 0 {
			// Nothing was appended to the journal this call — no rollback
			// needed, and no in-memory state has changed.
			return 0, fmt.Errorf("mirrorstore: append %q: write checkpoint: %w", logID, werr)
		}
		if renamed {
			// Post-rename ambiguous durability (P2-F): checkpoint.json ALREADY
			// names the new size (only its dir-fsync failed). Truncating the
			// journal back to preSize would put the checkpoint AHEAD of the
			// records — poisoned-inconsistent on reopen. Leave the journal at
			// the appended size (it matches the committed checkpoint) and
			// poison this log for the rest of the process; a fresh Open
			// reconciles from disk without ever seeing checkpoint-ahead.
			return 0, s.poison(key, dir, e, existed, logID, fmt.Errorf(
				"checkpoint rename committed but its durability is uncertain: %w", werr))
		}
		// Pre-rename failure: no durable checkpoint names the new records —
		// safe to roll them back (poison if the rollback itself fails).
		if rerr := truncateJournal(dir, preSize); rerr != nil {
			return 0, s.poison(key, dir, e, existed, logID, fmt.Errorf(
				"checkpoint write failed and the rollback truncate also failed: checkpoint error: %v; truncate error: %w", werr, rerr))
		}
		return 0, fmt.Errorf("mirrorstore: append %q: write checkpoint: %w", logID, werr)
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

// poison marks logID's in-memory entry broken with poisonErr (creating the
// entry for a first-ever-seen log) and returns the wrapped error every
// subsequent call for that log will surface. Shared by every runtime
// rollback-failure / ambiguous-durability path so a damaged mirror stays
// loudly broken rather than silently diverging.
func (s *Store) poison(key, dir string, e *logEntry, existed bool, logID string, cause error) error {
	if existed {
		e.poisonErr = cause
	} else {
		s.logs[key] = &logEntry{dir: dir, poisonErr: cause}
	}
	return fmt.Errorf("mirrorstore: append %q: %w", logID, cause)
}
