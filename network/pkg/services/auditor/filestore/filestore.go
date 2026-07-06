// Package filestore is the file-backed implementation of the auditor's
// StatusStore, ReceiptStore, and AuditQueue — the durable audit half of the
// evidence substrate (spec: evidence-persistence, e2e finding #23).
//
// Layout (one versioned-envelope JSON file per entry, named by the head's
// content-address hex):
//
//	verdicts/<hex>.json   — {"v":1,...} around an auditor.AuditRecord
//	receipts/<hex>.json   — {"v":1,"consumed":[...]}
//	auditqueue/<hex>.json — {"v":1,"seq":N,"attempts":N}
//
// Keys are validated as content addresses before path construction; writes
// are atomic (temp + fsync + rename); each store carries a per-store mutex
// (rename protects single files, not read-modify-write sequences).
//
// Damage posture: verdicts and receipts are EVIDENCE — an unreadable or
// invalid entry is an error distinct from the wrapped auditor.ErrNotFound,
// never absence (a damaged verdict must not read as "never audited"; a
// damaged receipt must not silently downgrade an aggregate audit to
// linear-only). Envelope reads VALIDATE, not just parse: AuditRecord's
// meaningful zero values (ConfidenceFailed == 0, fail-closed zero AxisResult)
// make a missing field indistinguishable from an intentional Failed, so
// version, enum ranges, a non-zero AuditedAt, and scope semantics are checked
// explicitly. The queue is reconstructible WORKING STATE — a damaged entry is
// skipped (with a warning) by ListNewest and repaired wholesale by Add.
package filestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

func entryFile(dir, hash string) (string, error) {
	if !vc.IsContentAddress(hash) {
		return "", fmt.Errorf("auditor/filestore: %q is not a sha256:<hex> content address", hash)
	}
	return filepath.Join(dir, strings.TrimPrefix(hash, "sha256:")+".json"), nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Make the directory entry durable too: without a dir fsync a power loss
	// after the rename can lose the entry even though the caller was told it
	// was recorded (the keystore/filestore idiom).
	return fsyncDir(filepath.Dir(path))
}

// fsyncDir flushes a directory's entry table (rename durability).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// mkdir creates dir if needed, PROVES it is writable (MkdirAll succeeds on an
// existing read-only dir — the boot must fail closed, not the first Put), and
// sweeps orphaned temp files from interrupted writes.
func mkdir(dir, what string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("auditor/filestore: create %s store %s: %w", what, dir, err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("auditor/filestore: %s store %s not writable: %w", what, dir, err)
	}
	probe.Close()
	os.Remove(probe.Name())
	des, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("auditor/filestore: list %s store %s: %w", what, dir, err)
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			os.Remove(filepath.Join(dir, de.Name()))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// StatusStore
// ---------------------------------------------------------------------------

// verdictEnvelope is the on-disk shape of one audit verdict.
type verdictEnvelope struct {
	V                         int                `json:"v"`
	Overall                   vc.ConfidenceState `json:"overall"`
	DataIntegrity             vc.ConfidenceState `json:"data_integrity"`
	SignerAuthenticity        vc.ConfidenceState `json:"signer_authenticity"`
	ChainConsistency          vc.ConfidenceState `json:"chain_consistency"`
	Notations                 []string           `json:"notations,omitempty"`
	SourceCommitment          vc.ConfidenceState `json:"source_commitment"`
	SourceCommitmentNotations []string           `json:"source_commitment_notations,omitempty"`
	LinearChain               bool               `json:"linear_chain"`
	SourceCommitmentEvaluated bool               `json:"source_commitment_evaluated"`
	AuditedAt                 time.Time          `json:"audited_at"`
}

func stateInRange(s vc.ConfidenceState) bool {
	return s >= vc.ConfidenceFailed && s <= vc.ConfidenceVerified
}

// validate rejects an envelope whose fields cannot have been written by Put:
// plain JSON cannot distinguish a missing field from an intentional zero
// (ConfidenceFailed), so the checkable invariants are enforced explicitly.
func (e verdictEnvelope) validate() error {
	if e.V != 1 {
		return fmt.Errorf("unsupported envelope version %d", e.V)
	}
	if e.AuditedAt.IsZero() {
		return errors.New("zero audited_at")
	}
	for _, s := range []vc.ConfidenceState{e.Overall, e.DataIntegrity, e.SignerAuthenticity, e.ChainConsistency, e.SourceCommitment} {
		if !stateInRange(s) {
			return fmt.Errorf("confidence state %d out of range", s)
		}
	}
	if !e.SourceCommitmentEvaluated && (e.SourceCommitment != vc.ConfidenceFailed || len(e.SourceCommitmentNotations) != 0) {
		return errors.New("source-commitment fields set without source_commitment_evaluated")
	}
	return nil
}

// StatusStore is the file-backed auditor.StatusStore.
type StatusStore struct {
	mu  sync.RWMutex
	dir string
}

var _ auditor.StatusStore = (*StatusStore)(nil)

// NewStatusStore opens (creating if needed) the verdict store rooted at dir.
func NewStatusStore(dir string) (*StatusStore, error) {
	if err := mkdir(dir, "verdict"); err != nil {
		return nil, err
	}
	return &StatusStore{dir: dir}, nil
}

// Put records rec for headHash (latest audit wins).
func (s *StatusStore) Put(headHash string, rec auditor.AuditRecord) error {
	path, err := entryFile(s.dir, headHash)
	if err != nil {
		return err
	}
	env := verdictEnvelope{
		V: 1, Overall: rec.Overall,
		DataIntegrity:      rec.Axes.DataIntegrity,
		SignerAuthenticity: rec.Axes.SignerAuthenticity,
		ChainConsistency:   rec.Axes.ChainConsistency,
		Notations:          rec.Notations,
		SourceCommitment:   rec.SourceCommitment, SourceCommitmentNotations: rec.SourceCommitmentNotations,
		LinearChain: rec.Scope.LinearChain, SourceCommitmentEvaluated: rec.Scope.SourceCommitmentEvaluated,
		AuditedAt: rec.AuditedAt,
	}
	// A local storage envelope, never hashed or signed over — not a signing
	// scope (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("auditor/filestore: marshal verdict %s: %w", headHash, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeAtomic(path, raw); err != nil {
		return fmt.Errorf("auditor/filestore: write verdict %s: %w", headHash, err)
	}
	return nil
}

// Get returns the recorded verdict, a wrapped auditor.ErrNotFound when none
// exists, or a distinct damaged-entry error.
func (s *StatusStore) Get(headHash string) (auditor.AuditRecord, error) {
	path, err := entryFile(s.dir, headHash)
	if err != nil {
		return auditor.AuditRecord{}, err
	}
	s.mu.RLock()
	raw, err := os.ReadFile(path)
	s.mu.RUnlock()
	if errors.Is(err, fs.ErrNotExist) {
		// A vanished store root is storage damage, not an unaudited head.
		if _, statErr := os.Stat(s.dir); statErr != nil {
			return auditor.AuditRecord{}, fmt.Errorf("auditor/filestore: verdict store root %s unavailable: %w", s.dir, statErr)
		}
		return auditor.AuditRecord{}, fmt.Errorf("%w: %q", auditor.ErrNotFound, headHash)
	}
	if err != nil {
		return auditor.AuditRecord{}, fmt.Errorf("auditor/filestore: read verdict %s: %w", headHash, err)
	}
	var env verdictEnvelope
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return auditor.AuditRecord{}, fmt.Errorf("auditor/filestore: damaged verdict entry %s: %w", headHash, err)
	}
	if err := env.validate(); err != nil {
		return auditor.AuditRecord{}, fmt.Errorf("auditor/filestore: damaged verdict entry %s: %w", headHash, err)
	}
	return auditor.AuditRecord{
		Overall: env.Overall,
		Axes: vc.AxisResult{
			DataIntegrity:      env.DataIntegrity,
			SignerAuthenticity: env.SignerAuthenticity,
			ChainConsistency:   env.ChainConsistency,
		},
		Notations:        env.Notations,
		SourceCommitment: env.SourceCommitment, SourceCommitmentNotations: env.SourceCommitmentNotations,
		Scope:     auditor.AuditScope{LinearChain: env.LinearChain, SourceCommitmentEvaluated: env.SourceCommitmentEvaluated},
		AuditedAt: env.AuditedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// ReceiptStore
// ---------------------------------------------------------------------------

type receiptEnvelope struct {
	V        int      `json:"v"`
	Consumed []string `json:"consumed"`
}

// ReceiptStore is the file-backed auditor.ReceiptStore.
type ReceiptStore struct {
	mu  sync.RWMutex
	dir string
}

var _ auditor.ReceiptStore = (*ReceiptStore)(nil)

// NewReceiptStore opens (creating if needed) the receipt store rooted at dir.
func NewReceiptStore(dir string) (*ReceiptStore, error) {
	if err := mkdir(dir, "receipt"); err != nil {
		return nil, err
	}
	return &ReceiptStore{dir: dir}, nil
}

// Put records the consumed source content addresses for an emitted head.
func (s *ReceiptStore) Put(headHash string, consumedHashes []string) error {
	path, err := entryFile(s.dir, headHash)
	if err != nil {
		return err
	}
	cp := make([]string, len(consumedHashes))
	copy(cp, consumedHashes)
	// A local storage envelope, never hashed or signed over — not a signing
	// scope (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(receiptEnvelope{V: 1, Consumed: cp})
	if err != nil {
		return fmt.Errorf("auditor/filestore: marshal receipt %s: %w", headHash, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeAtomic(path, raw); err != nil {
		return fmt.Errorf("auditor/filestore: write receipt %s: %w", headHash, err)
	}
	return nil
}

// Get returns the consumed set, a wrapped auditor.ErrNotFound when no receipt
// exists, or a distinct damaged-entry error (which the audit runner fails
// closed on — never a silent downgrade to linear-only).
func (s *ReceiptStore) Get(headHash string) ([]string, error) {
	path, err := entryFile(s.dir, headHash)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	raw, err := os.ReadFile(path)
	s.mu.RUnlock()
	if errors.Is(err, fs.ErrNotExist) {
		// A vanished store root is storage damage, not "no receipt" — reading
		// it as absence would silently downgrade aggregate audits to
		// linear-only on receipt-store loss.
		if _, statErr := os.Stat(s.dir); statErr != nil {
			return nil, fmt.Errorf("auditor/filestore: receipt store root %s unavailable: %w", s.dir, statErr)
		}
		return nil, fmt.Errorf("%w: no receipt for %q", auditor.ErrNotFound, headHash)
	}
	if err != nil {
		return nil, fmt.Errorf("auditor/filestore: read receipt %s: %w", headHash, err)
	}
	var env receiptEnvelope
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return nil, fmt.Errorf("auditor/filestore: damaged receipt entry %s: %w", headHash, err)
	}
	if env.V != 1 || env.Consumed == nil {
		return nil, fmt.Errorf("auditor/filestore: damaged receipt entry %s: version %d / missing consumed", headHash, env.V)
	}
	return env.Consumed, nil
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

type queueEnvelope struct {
	V        int   `json:"v"`
	Seq      int64 `json:"seq"`
	Attempts int   `json:"attempts"`
}

// Queue is the file-backed auditor.AuditQueue: newest-first by embedded seq,
// deduped by head hash, attempts preserved across re-registration AND across
// restart.
type Queue struct {
	mu      sync.Mutex
	dir     string
	nextSeq int64
	logger  *slog.Logger
}

var _ auditor.AuditQueue = (*Queue)(nil)

// NewQueue opens (creating if needed) the audit queue rooted at dir,
// recovering the ordering sequence from existing entries.
func NewQueue(dir string) (*Queue, error) {
	if err := mkdir(dir, "audit-queue"); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, logger: slog.Default()}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("auditor/filestore: list audit queue %s: %w", dir, err)
	}
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		env, err := q.readEnvelope(filepath.Join(dir, de.Name()))
		if err != nil {
			continue // recovered lazily; ListNewest warns
		}
		if env.Seq >= q.nextSeq {
			q.nextSeq = env.Seq + 1
		}
	}
	return q, nil
}

func (q *Queue) readEnvelope(path string) (queueEnvelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return queueEnvelope{}, err
	}
	var env queueEnvelope
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return queueEnvelope{}, err
	}
	if env.V != 1 || env.Attempts < 0 {
		return queueEnvelope{}, fmt.Errorf("invalid entry (v %d, attempts %d)", env.V, env.Attempts)
	}
	return env, nil
}

func (q *Queue) write(hash string, env queueEnvelope) error {
	path, err := entryFile(q.dir, hash)
	if err != nil {
		return err
	}
	// A local storage envelope, never hashed or signed over — not a signing
	// scope (canonicalizer-hygiene-exempt).
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return writeAtomic(path, raw)
}

// Add registers headHash newest-first; a re-add is a no-op that preserves
// Attempts (re-consuming the same content address must not reset progress).
func (q *Queue) Add(headHash string) error {
	path, err := entryFile(q.dir, headHash)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, err := q.readEnvelope(path); err == nil {
		return nil // already queued — preserve attempts and position
	} else if !errors.Is(err, fs.ErrNotExist) {
		q.logger.Warn("auditor/filestore: replacing damaged queue entry", "hash", headHash, "err", err)
	}
	if err := q.write(headHash, queueEnvelope{V: 1, Seq: q.nextSeq}); err != nil {
		return err
	}
	q.nextSeq++
	return nil
}

// ListNewest returns up to n candidates, newest first (by seq), skipping
// damaged entries with a warning (working state — one damaged entry must not
// stall the audit loop).
func (q *Queue) ListNewest(n int) ([]auditor.AuditCandidate, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	des, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, fmt.Errorf("auditor/filestore: list audit queue %s: %w", q.dir, err)
	}
	type cand struct {
		hash string
		env  queueEnvelope
	}
	all := make([]cand, 0, len(des))
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		hash := "sha256:" + strings.TrimSuffix(de.Name(), ".json")
		if !vc.IsContentAddress(hash) {
			// A stray well-formed envelope under a non-hex name would become an
			// unremovable candidate (Remove validates the key) and burn a batch
			// slot every tick — skip foreign filenames outright.
			q.logger.Warn("auditor/filestore: skipping foreign file in queue dir", "file", de.Name())
			continue
		}
		env, err := q.readEnvelope(filepath.Join(q.dir, de.Name()))
		if err != nil {
			q.logger.Warn("auditor/filestore: skipping damaged queue entry", "file", de.Name(), "err", err)
			continue
		}
		all = append(all, cand{hash: hash, env: env})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].env.Seq > all[j].env.Seq })
	out := make([]auditor.AuditCandidate, 0, n)
	for _, c := range all {
		if len(out) >= n {
			break
		}
		out = append(out, auditor.AuditCandidate{HeadHash: c.hash, Attempts: c.env.Attempts})
	}
	return out, nil
}

// Remove drops headHash; removing an absent hash is a no-op.
func (q *Queue) Remove(headHash string) error {
	path, err := entryFile(q.dir, headHash)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("auditor/filestore: remove queue entry %s: %w", headHash, err)
	}
	return nil
}

// IncrementAttempt bumps the attempt counter, or auditor.ErrNotQueued.
func (q *Queue) IncrementAttempt(headHash string) error {
	path, err := entryFile(q.dir, headHash)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	env, err := q.readEnvelope(path)
	if errors.Is(err, fs.ErrNotExist) {
		return auditor.ErrNotQueued
	}
	if err != nil {
		return fmt.Errorf("auditor/filestore: queue entry %s: %w", headHash, err)
	}
	env.Attempts++
	return q.write(headHash, env)
}

// Len reports the number of queued heads (damaged entries included — they
// occupy the queue until repaired or removed).
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	des, err := os.ReadDir(q.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, de := range des {
		if !de.IsDir() && strings.HasSuffix(de.Name(), ".json") {
			n++
		}
	}
	return n
}
