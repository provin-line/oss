// Package filestore is the file-backed implementation of the vcresolver Store
// and Pool — the durable evidence substrate (spec: evidence-persistence,
// driven by e2e finding #23: a restart must not erase the audit evidence).
//
// Layout (one JSON file per entry under the store's root):
//
//	credentials/<hex>.json — the credential's canonical JSON (MarshalJSON),
//	                         byte-identical to what ResolveVC serves
//	pool/<hex>.json        — {"v":1,"seq":N,...} envelope around an
//	                         UnresolvedEntry
//
// Every key is validated as a content address (vc.IsContentAddress) BEFORE
// path construction — the hex payload is then filesystem-safe by
// construction. Writes are atomic (temp + fsync + rename, the repo idiom);
// a crash mid-write leaves an orphaned temp file, never a torn entry.
// Rename-atomicity protects single files, not read-modify-write sequences,
// so each store carries a per-store mutex exactly like its mem sibling.
//
// Damage posture: the credential store is EVIDENCE — a Get that hits an
// unreadable or tampered file (the decoded body's content address is
// recomputed and must equal the key) is an error, never ErrNotFound. The
// pool is reconstructible WORKING STATE — a corrupt entry is skipped with a
// warning in ListNewest (one damaged scheduling entry must not stall every
// drain) but surfaces as an error from Get.
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

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// entryFile converts a validated content address to its file path under dir.
func entryFile(dir, hash string) (string, error) {
	if !vc.IsContentAddress(hash) {
		return "", fmt.Errorf("%w: %q is not a sha256:<hex> content address", vcresolver.ErrInvalidArgument, hash)
	}
	return filepath.Join(dir, strings.TrimPrefix(hash, "sha256:")+".json"), nil
}

// writeAtomic writes data to path via temp + fsync + rename (crash-safe: a
// reader observes the old entry or the new one, never a torn one).
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
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

// openDir creates dir if needed, PROVES it is writable (MkdirAll succeeds on
// an existing read-only dir — the boot must fail closed, not the first Put),
// and sweeps orphaned temp files from interrupted writes.
func openDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("not writable: %w", err)
	}
	probe.Close()
	os.Remove(probe.Name())
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			os.Remove(filepath.Join(dir, de.Name()))
		}
	}
	return nil
}

// poolEnvelope is the on-disk shape of one unresolved-pool entry: a versioned
// envelope so a later format change can migrate instead of guessing. Seq is
// the newest-first ordering key (monotonic per store lifetime, recovered as
// max(existing)+1 on open — no shared counter file).
type poolEnvelope struct {
	V   int   `json:"v"`
	Seq int64 `json:"seq"`

	Hash             string `json:"hash"`
	UpstreamEndpoint string `json:"upstream_endpoint,omitempty"`
	ReferrerIssuer   string `json:"referrer_issuer,omitempty"`
	RetryCount       int    `json:"retry_count"`
	AssemblyDepth    int    `json:"assembly_depth"`
}

// Pool is the file-backed vcresolver.Pool (plus the batchresolver Get and
// audit-runner Has seams): one envelope file per queued hole.
type Pool struct {
	mu      sync.Mutex
	dir     string
	nextSeq int64
	logger  *slog.Logger
}

var _ vcresolver.Pool = (*Pool)(nil)

// NewPool opens (creating if needed) the unresolved pool rooted at dir,
// recovering the ordering sequence from existing entries.
func NewPool(dir string) (*Pool, error) {
	if err := openDir(dir); err != nil {
		return nil, fmt.Errorf("filestore: open pool %s: %w", dir, err)
	}
	p := &Pool{dir: dir, logger: slog.Default()}
	entries, err := p.loadAll()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Seq >= p.nextSeq {
			p.nextSeq = e.Seq + 1
		}
	}
	return p, nil
}

// loadAll reads every well-formed envelope in the pool dir, skipping (with a
// warning) damaged entries and foreign files — the pool is reconstructible
// working state; one damaged scheduling entry must not stall every drain.
func (p *Pool) loadAll() ([]poolEnvelope, error) {
	des, err := os.ReadDir(p.dir)
	if err != nil {
		return nil, fmt.Errorf("filestore: list pool %s: %w", p.dir, err)
	}
	out := make([]poolEnvelope, 0, len(des))
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		env, err := p.readEnvelope(filepath.Join(p.dir, de.Name()))
		if err != nil {
			p.logger.Warn("filestore: skipping damaged pool entry", "file", de.Name(), "err", err)
			continue
		}
		// A misfiled entry (envelope hash != filename) would be listed under a
		// hash whose Remove deletes a different, absent path — a perpetual
		// list occupant. Treat it as damage and skip.
		if want := "sha256:" + strings.TrimSuffix(de.Name(), ".json"); env.Hash != want {
			p.logger.Warn("filestore: skipping misfiled pool entry", "file", de.Name(), "envelope_hash", env.Hash)
			continue
		}
		out = append(out, env)
	}
	return out, nil
}

func (p *Pool) readEnvelope(path string) (poolEnvelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return poolEnvelope{}, err
	}
	var env poolEnvelope
	if err := canon.NewStrictDecoder(raw).Decode(&env); err != nil {
		return poolEnvelope{}, err
	}
	if env.V != 1 {
		return poolEnvelope{}, fmt.Errorf("unsupported envelope version %d", env.V)
	}
	if !vc.IsContentAddress(env.Hash) || env.AssemblyDepth < 1 {
		return poolEnvelope{}, fmt.Errorf("invalid entry (hash %q, depth %d)", env.Hash, env.AssemblyDepth)
	}
	return env, nil
}

func (p *Pool) writeEnvelope(env poolEnvelope) error {
	path, err := entryFile(p.dir, env.Hash)
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

// Add upserts e keyed by Hash, reproducing the mem pool's merge exactly: a
// new hole gets the next seq (newest-first); a re-added hole is not
// duplicated but has empty hints filled (a non-empty hint is never clobbered
// with an empty one), RetryCount preserved, and the MINIMUM AssemblyDepth
// kept. A non-positive AssemblyDepth is rejected (a real hole is >= 1).
func (p *Pool) Add(e vcresolver.UnresolvedEntry) error {
	if e.AssemblyDepth < 1 {
		return fmt.Errorf("%w: AssemblyDepth %d must be >= 1", vcresolver.ErrInvalidArgument, e.AssemblyDepth)
	}
	path, err := entryFile(p.dir, e.Hash)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, err := p.readEnvelope(path); err == nil {
		if existing.UpstreamEndpoint == "" {
			existing.UpstreamEndpoint = e.UpstreamEndpoint
		}
		if existing.ReferrerIssuer == "" {
			existing.ReferrerIssuer = e.ReferrerIssuer
		}
		if e.AssemblyDepth < existing.AssemblyDepth {
			existing.AssemblyDepth = e.AssemblyDepth
		}
		return p.writeEnvelope(existing)
	} else if !errors.Is(err, fs.ErrNotExist) {
		// A damaged entry is replaced wholesale: working state, latest wins.
		p.logger.Warn("filestore: replacing damaged pool entry", "hash", e.Hash, "err", err)
	}
	env := poolEnvelope{
		V: 1, Seq: p.nextSeq,
		Hash: e.Hash, UpstreamEndpoint: e.UpstreamEndpoint,
		ReferrerIssuer: e.ReferrerIssuer, RetryCount: e.RetryCount, AssemblyDepth: e.AssemblyDepth,
	}
	if err := p.writeEnvelope(env); err != nil {
		return err
	}
	p.nextSeq++
	return nil
}

// Get returns the live entry at hash and whether it is present (the batch
// resolver re-reads before acting). A damaged entry reads as absent here —
// consistent with the skip-in-list posture — after a logged warning.
func (p *Pool) Get(hash string) (vcresolver.UnresolvedEntry, bool) {
	path, err := entryFile(p.dir, hash)
	if err != nil {
		return vcresolver.UnresolvedEntry{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	env, err := p.readEnvelope(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			p.logger.Warn("filestore: damaged pool entry read as absent", "hash", hash, "err", err)
		}
		return vcresolver.UnresolvedEntry{}, false
	}
	return env.entry(), true
}

func (env poolEnvelope) entry() vcresolver.UnresolvedEntry {
	return vcresolver.UnresolvedEntry{
		Hash: env.Hash, UpstreamEndpoint: env.UpstreamEndpoint,
		ReferrerIssuer: env.ReferrerIssuer, RetryCount: env.RetryCount, AssemblyDepth: env.AssemblyDepth,
	}
}

// ListNewest returns up to n entries, newest first (by seq).
func (p *Pool) ListNewest(n int) ([]vcresolver.UnresolvedEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	envs, err := p.loadAll()
	if err != nil {
		return nil, err
	}
	sort.Slice(envs, func(i, j int) bool { return envs[i].Seq > envs[j].Seq })
	out := make([]vcresolver.UnresolvedEntry, 0, n)
	for _, env := range envs {
		if len(out) >= n {
			break
		}
		out = append(out, env.entry())
	}
	return out, nil
}

// Remove drops the entry at hash. Removing an absent hash is a no-op.
func (p *Pool) Remove(hash string) error {
	path, err := entryFile(p.dir, hash)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("filestore: remove pool entry %s: %w", hash, err)
	}
	return nil
}

// IncrementRetry bumps the retry counter for hash, or vcresolver.ErrNotFound.
func (p *Pool) IncrementRetry(hash string) error {
	path, err := entryFile(p.dir, hash)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	env, err := p.readEnvelope(path)
	if errors.Is(err, fs.ErrNotExist) {
		return vcresolver.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("filestore: pool entry %s: %w", hash, err)
	}
	env.RetryCount++
	return p.writeEnvelope(env)
}

// Has reports whether a hole is currently queued (the audit runner's
// liveness signal). A damaged entry still counts as queued — the resolver
// has not given up on it (Add will repair it wholesale).
func (p *Pool) Has(hash string) bool {
	path, err := entryFile(p.dir, hash)
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, statErr := os.Stat(path)
	return statErr == nil
}

// Len reports the number of queued holes (damaged entries included — they
// occupy the queue until repaired or removed).
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	des, err := os.ReadDir(p.dir)
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
