package filelog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/tlog"
)

// Archive layout constants. A rotated segment is assembled under a dot-prefixed
// staging directory and atomically renamed to its final seg-NNNNNN name, so an
// interrupted rotation never leaves a partial directory that numbering counts.
const (
	archiveDir      = "archive"
	segmentPrefix   = "seg-"
	manifestFile    = "manifest.json"
	rotateMarker    = ".rotate-intent"
	rotateMarkerTmp = ".rotate-intent.tmp"
	// segmentHW persists the highest-allocated segment number in the LOG dir (not
	// under archive/), so moving archived segments to cold storage never resets
	// numbering — a reset would let two rotations both claim seg-000001 and break
	// the segment ordering audit stitching relies on.
	segmentHWFile = ".segment-hw"
	segmentHWTmp  = ".segment-hw.tmp"
)

// RotatedSegment describes the archived log segment a Rotate produced. It is a
// STORAGE-rotation record, not a cryptographic seal: Head is a chain-head hash
// summary (integrity is chain replay + filesystem access control — the same
// trust model as the unsigned live log). Checkpoint is a genuine signed seal
// ONLY when the log was armed with a CheckpointSigner; it is nil otherwise.
//
// Signed caveat: the archived Checkpoint is stamped with the log's LogID, which
// the continuing live log keeps using after rotation restarts at size 0. A
// verifier that tracks consistency proofs across rotation for a stable LogID
// would see size regress S→0 and read it as tampering. So Rotate is safe today
// for the wired use (the unsigned relationship-evidence log) and for one-shot
// segment sealing, but arming a consistency-proof-continuous log for rotation
// needs a per-segment log identity first (post-v0; see the I-2 spec non-goals).
type RotatedSegment struct {
	// Path is the absolute path to the archive segment directory.
	Path string
	// Segment is the monotonic segment number (ordering across rotations).
	Segment uint64
	// Size is the record count copied into this segment (Rotate rejects Size==0).
	Size uint64
	// Head is the chain head hash of the segment (storage integrity summary).
	Head string
	// Genesis is the first record's chain hash (segment stitching / order aid).
	Genesis string
	// RotatedAt is when the rotation committed.
	RotatedAt time.Time
	// Checkpoint is the signed final commitment IFF a signer is armed; else nil.
	Checkpoint *tlog.Checkpoint
}

// segmentManifest is the on-disk manifest.json in an archive segment.
type segmentManifest struct {
	V          int              `json:"v"`
	Segment    uint64           `json:"segment"`
	RotatedAt  string           `json:"rotatedAt"`
	Size       uint64           `json:"size"`
	Head       string           `json:"head"`
	Genesis    string           `json:"genesis"`
	Checkpoint *tlog.Checkpoint `json:"checkpoint,omitempty"`
}

// rotateIntent is the durable <dir>/.rotate-intent marker naming the segment a
// rotation is committing. It is the SOLE authority for crash reconciliation:
// the equal-heads coincidence of a fresh live segment must never drive a
// destructive truncate, so recovery keys on this marker, never on a value
// comparison alone.
type rotateIntent struct {
	Segment uint64 `json:"segment"`
	Size    uint64 `json:"size"`
	Head    string `json:"head"`
}

// Rotate copies the current log into a cold-archive segment under the log
// directory, then truncates the live log in place to a fresh empty genesis.
// Records are never mutated or deleted (the tlog append-only contract holds);
// the archived segment stays independently replay-verifiable and — if the log
// is armed with a CheckpointSigner — carries a signed final Checkpoint.
// Truncating in place preserves the log file's inode, so the single-opener
// flock keeps holding throughout: no rename window, no fresh-file relock race.
// The emission-sequence intent high-water is preserved (anti-reuse state, not
// chain data). Rotate errors on an empty log. Crash recovery is handled at the
// next New via the durable rotation-intent marker (Rotate itself keeps no
// re-entry idempotency: an unreconciled marker fails loud — reopen first).
func (l *Log) Rotate(_ context.Context) (*RotatedSegment, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, errors.New("filelog: rotate on a closed log")
	}
	if l.broken {
		return nil, errors.New("filelog: rotate on a poisoned log")
	}
	// A marker here means a prior rotation crashed and New has not reconciled it.
	// Refuse to guess a half-finished state; the operator must reopen the log.
	if present, err := markerPresent(l.dir); err != nil {
		return nil, err
	} else if present {
		return nil, fmt.Errorf("filelog: unreconciled rotation marker in %s — reopen the log before rotating", l.dir)
	}
	size := uint64(len(l.records))
	if size == 0 {
		return nil, errors.New("filelog: rotate on an empty log (nothing to archive)")
	}
	head := l.records[size-1].Hash
	genesis := l.records[0].Hash
	rotatedAt := time.Now().UTC().Truncate(time.Second)

	// Signed seal only if armed. We hold l.mu, so seal through the lock-free
	// helper — the public Checkpoint would re-lock l.mu and deadlock.
	var cp *tlog.Checkpoint
	if l.signer != nil {
		c, err := signCheckpoint(size, head, l.signer, rotatedAt)
		if err != nil {
			return nil, err
		}
		cp = c
	}

	seg, err := allocateSegment(l.dir)
	if err != nil {
		return nil, err
	}
	finalDir := filepath.Join(l.dir, archiveDir, segmentName(seg))

	// (3) durable intent: "records 0..size-1 are being archived as seg-N".
	if err := writeMarker(l.dir, rotateIntent{Segment: seg, Size: size, Head: head}); err != nil {
		return nil, err
	}
	// (4) assemble the segment under a staging dir, then (5) atomically rename it
	// into place — the commit point. Only after that is the archive durable.
	manifest := segmentManifest{
		V: 1, Segment: seg, RotatedAt: rotatedAt.Format(time.RFC3339),
		Size: size, Head: head, Genesis: genesis, Checkpoint: cp,
	}
	if err := assembleSegment(l.dir, seg, manifest); err != nil {
		return nil, err
	}
	// (6) truncate the live log in place (inode preserved → flock retained). Reset
	// in-memory state ONLY after truncate+fsync succeed; a failure leaves the log
	// unusable rather than falsely claiming rotation completed.
	if err := l.file.Truncate(0); err != nil {
		return nil, fmt.Errorf("filelog: truncate live log after archiving seg %d: %w", seg, err)
	}
	if err := l.file.Sync(); err != nil {
		return nil, fmt.Errorf("filelog: fsync truncated live log: %w", err)
	}
	if err := fsyncDir(l.dir); err != nil {
		return nil, err
	}
	l.records = nil
	l.size = 0
	// (7) drop the marker: rotation is complete.
	if err := removeMarker(l.dir); err != nil {
		return nil, err
	}
	return &RotatedSegment{
		Path: finalDir, Segment: seg, Size: size, Head: head,
		Genesis: genesis, RotatedAt: rotatedAt, Checkpoint: cp,
	}, nil
}

// reconcileRotation completes or rolls back a rotation interrupted by a crash.
// Called by New (holding the flock, before any Append). It is a no-op when no
// marker is present.
func (l *Log) reconcileRotation() error {
	ri, present, err := readMarker(l.dir)
	if err != nil {
		return err // malformed marker: fail closed.
	}
	if !present {
		return nil
	}
	segDir := filepath.Join(l.dir, archiveDir, segmentName(ri.Segment))
	committed, err := segmentMatches(segDir, ri)
	if err != nil {
		// The segment exists but is malformed or disagrees with the marker: an
		// ambiguous, damaged state. Fail loud rather than silently rolling back a
		// numbered segment that may be corrupt.
		return fmt.Errorf("filelog: interrupted rotation: archive segment %s does not match marker: %w", segDir, err)
	}
	if committed {
		// The archive is durable. Finish the live truncation if it did not run.
		switch uint64(len(l.records)) {
		case ri.Size:
			if l.records[ri.Size-1].Hash != ri.Head {
				return fmt.Errorf("filelog: interrupted rotation: live head %q != marker head %q", l.records[ri.Size-1].Hash, ri.Head)
			}
			if err := l.file.Truncate(0); err != nil {
				return fmt.Errorf("filelog: reconcile truncate: %w", err)
			}
			if err := l.file.Sync(); err != nil {
				return fmt.Errorf("filelog: reconcile fsync: %w", err)
			}
			if err := fsyncDir(l.dir); err != nil {
				return err
			}
			l.records = nil
			l.size = 0
		case 0:
			// Truncate already ran before the crash; nothing to complete.
		default:
			return fmt.Errorf("filelog: interrupted rotation: live log has %d records, expected %d or 0", len(l.records), ri.Size)
		}
		return removeMarker(l.dir)
	}
	// The segment was never committed. An uncommitted rotation never truncated,
	// so the live log must still hold exactly the 0..size-1 it did at the crash.
	// Anything else means a committed segment vanished (e.g. a lost archive link,
	// or manual deletion) — fail loud rather than silently accept a short log.
	if uint64(len(l.records)) != ri.Size {
		return fmt.Errorf("filelog: interrupted rotation: segment %d uncommitted but live log has %d records, expected %d — an archive segment may be lost", ri.Segment, len(l.records), ri.Size)
	}
	// Discard any staging remnant and drop the marker; the live log is authoritative.
	if err := os.RemoveAll(segmentTmp(l.dir, ri.Segment)); err != nil {
		return fmt.Errorf("filelog: reconcile remove staging: %w", err)
	}
	if err := fsyncDirIfExists(filepath.Join(l.dir, archiveDir)); err != nil {
		return err
	}
	return removeMarker(l.dir)
}

// segmentMatches reports whether segDir holds a committed segment matching ri.
// segDir absent -> (false, nil): uncommitted, caller rolls back. Present and its
// replayed chain matches ri (size and head) -> (true, nil). Present but replay
// fails or disagrees -> (false, err): the caller fails loud.
func segmentMatches(segDir string, ri rotateIntent) (bool, error) {
	if _, err := os.Stat(segDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("filelog: stat segment %s: %w", segDir, err)
	}
	records, keep, err := replay(filepath.Join(segDir, logFile))
	if err != nil {
		return false, err
	}
	if keep >= 0 {
		return false, fmt.Errorf("archived segment has a torn tail (kept %d bytes)", keep)
	}
	if uint64(len(records)) != ri.Size {
		return false, fmt.Errorf("archived size %d != marker size %d", len(records), ri.Size)
	}
	head := ""
	if n := len(records); n > 0 {
		head = records[n-1].Hash
	}
	if head != ri.Head {
		return false, fmt.Errorf("archived head %q != marker head %q", head, ri.Head)
	}
	return true, nil
}

// assembleSegment copies the live log bytes and writes the manifest into a
// staging dir, fsyncs both, then atomically renames the staging dir to its
// final seg-N name and fsyncs the archive dir. On return the segment is durable.
func assembleSegment(dir string, seg uint64, m segmentManifest) error {
	tmp := segmentTmp(dir, seg)
	final := filepath.Join(dir, archiveDir, segmentName(seg))
	// A leftover staging dir from an earlier crash must not poison this attempt.
	if err := os.RemoveAll(tmp); err != nil {
		return fmt.Errorf("filelog: clear staging %s: %w", tmp, err)
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return fmt.Errorf("filelog: create staging %s: %w", tmp, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, logFile))
	if err != nil {
		return fmt.Errorf("filelog: read live log for archive: %w", err)
	}
	if err := writeFileSync(filepath.Join(tmp, logFile), data, 0o600); err != nil {
		return err
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("filelog: marshal manifest: %w", err)
	}
	if err := writeFileSync(filepath.Join(tmp, manifestFile), mb, 0o600); err != nil {
		return err
	}
	if err := fsyncDir(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("filelog: commit segment %s: %w", final, err)
	}
	if err := fsyncDir(filepath.Join(dir, archiveDir)); err != nil {
		return err
	}
	// Persist archive/'s own link into the parent log dir BEFORE the caller makes
	// the destructive live truncate durable. On the first rotation the archive/
	// directory entry is newly created; without this fsync a crash could lose the
	// whole segment (its link into dir) while the live log is already truncated —
	// silent audit-record loss, the exact failure this slice exists to prevent.
	return fsyncDir(dir)
}

// allocateSegment durably reserves and returns the next segment number. The
// high-water is persisted BEFORE the segment is assembled, so a number is never
// reused even if the rotation later rolls back (a rolled-back number just leaves
// a harmless gap). It is derived from max(persisted high-water, highest on-disk
// seg-N) so numbering stays correct whether or not archived segments have been
// moved to cold storage. Monotonic, never reset.
func allocateSegment(dir string) (uint64, error) {
	hw, err := loadSegmentHW(dir)
	if err != nil {
		return 0, err
	}
	scanMax, err := scanArchiveMax(dir)
	if err != nil {
		return 0, err
	}
	seg := hw
	if scanMax > seg {
		seg = scanMax
	}
	seg++
	if err := persistSegmentHW(dir, seg); err != nil {
		return 0, err
	}
	return seg, nil
}

// scanArchiveMax returns the highest seg-NNNNNN number in archive/ (0 if none or
// archive absent). Only fully-numeric seg- names count; dot-staging dirs and
// anything else are ignored. Defensive input to allocateSegment so numbering
// stays correct even if the high-water somehow trails the on-disk segments.
func scanArchiveMax(dir string) (uint64, error) {
	ents, err := os.ReadDir(filepath.Join(dir, archiveDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("filelog: scan archive: %w", err)
	}
	var max uint64
	for _, e := range ents {
		if n, ok := parseSegmentName(e.Name()); ok && n > max {
			max = n
		}
	}
	return max, nil
}

// loadSegmentHW reads the persisted high-water (0 if absent). Unlike the intent
// sidecar, a corrupt counter does NOT degrade to 0 — that would risk reissuing a
// live segment number and duplicating a seg dir. It fails loud so the operator
// repairs it (rotation is an offline action, so this blocks only the rotate).
func loadSegmentHW(dir string) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(dir, segmentHWFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("filelog: read segment high-water: %w", err)
	}
	hw, perr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if perr != nil {
		return 0, fmt.Errorf("filelog: segment high-water %q unparseable: %w", strings.TrimSpace(string(raw)), perr)
	}
	return hw, nil
}

// persistSegmentHW atomically records seg as the high-water (tmp → fsync →
// rename → fsync dir).
func persistSegmentHW(dir string, seg uint64) error {
	tmp := filepath.Join(dir, segmentHWTmp)
	if err := writeFileSync(tmp, []byte(strconv.FormatUint(seg, 10)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, segmentHWFile)); err != nil {
		return fmt.Errorf("filelog: persist segment high-water: %w", err)
	}
	return fsyncDir(dir)
}

// parseSegmentName extracts N from a strictly-formed "seg-<digits>" name.
func parseSegmentName(name string) (uint64, bool) {
	if !strings.HasPrefix(name, segmentPrefix) {
		return 0, false
	}
	num := strings.TrimPrefix(name, segmentPrefix)
	if num == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func segmentName(seg uint64) string { return fmt.Sprintf("%s%06d", segmentPrefix, seg) }

func segmentTmp(dir string, seg uint64) string {
	return filepath.Join(dir, archiveDir, "."+segmentName(seg)+".tmp")
}

func markerPath(dir string) string { return filepath.Join(dir, rotateMarker) }

func markerPresent(dir string) (bool, error) {
	if _, err := os.Stat(markerPath(dir)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("filelog: stat rotation marker: %w", err)
	}
	return true, nil
}

// writeMarker atomically installs the rotation-intent marker (tmp → fsync →
// rename → fsync dir), so a reader never sees a torn marker.
func writeMarker(dir string, ri rotateIntent) error {
	b, err := json.Marshal(ri)
	if err != nil {
		return fmt.Errorf("filelog: marshal rotation marker: %w", err)
	}
	tmp := filepath.Join(dir, rotateMarkerTmp)
	if err := writeFileSync(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, markerPath(dir)); err != nil {
		return fmt.Errorf("filelog: install rotation marker: %w", err)
	}
	return fsyncDir(dir)
}

// readMarker reads and strictly validates the marker. A present-but-invalid
// marker (unparseable, or zero segment/size or empty head) returns present=true
// with an error so reconciliation fails closed rather than proceeding blind.
func readMarker(dir string) (ri rotateIntent, present bool, err error) {
	b, err := os.ReadFile(markerPath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return rotateIntent{}, false, nil
	}
	if err != nil {
		return rotateIntent{}, false, fmt.Errorf("filelog: read rotation marker: %w", err)
	}
	if err := canon.NewStrictDecoder(b).Decode(&ri); err != nil {
		return rotateIntent{}, true, fmt.Errorf("filelog: malformed rotation marker: %w", err)
	}
	if ri.Segment == 0 || ri.Size == 0 || ri.Head == "" {
		return rotateIntent{}, true, fmt.Errorf("filelog: invalid rotation marker %+v", ri)
	}
	return ri, true, nil
}

func removeMarker(dir string) error {
	if err := os.Remove(markerPath(dir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filelog: remove rotation marker: %w", err)
	}
	return fsyncDir(dir)
}

// writeFileSync creates path (truncating), writes data, fsyncs, and closes.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("filelog: create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("filelog: write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("filelog: fsync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("filelog: close %s: %w", path, err)
	}
	return nil
}

// fsyncDirIfExists fsyncs dir, tolerating its absence (rollback may run before
// the archive dir was ever created).
func fsyncDirIfExists(dir string) error {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fsyncDir(dir)
}
