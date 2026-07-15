package filestore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
)

// Backend is the file-backed vcresolver.VariantBackend.
//
// Layout, under the credential store's root:
//
//	<bodyhex>.json                    — the legacy body-only slot
//	variants/<bodyhex>/<varianthex>.json — the append-only variant set
//
// The variant subtree is INVISIBLE to the pre-slice reader, and that is the
// rollback plan rather than a coincidence: the old Get opened exactly
// "<hex>.json" and the old ListHashes skipped directories, so an older binary
// run against this root still resolves every body through the flat slot the
// façade maintains, and never trips over a layout it does not know.
//
// This type holds no opinion about what it stores. Whether bytes are canonical,
// which variant a body projects, and whether a name may be reused are decided
// in vcresolver.VariantStore, above every backend. What lives HERE is what only
// a filesystem can answer: atomic create, durability, and enumeration.
type Backend struct {
	mu   sync.RWMutex
	dir  string
	vdir string
}

var _ vcresolver.VariantBackend = (*Backend)(nil)

const variantsSubdir = "variants"

// NewBackend opens (creating if needed) the variant-aware credential store
// rooted at dir. An uncreatable root is an error — a node that cannot persist
// evidence must not pretend to (boot fails closed).
func NewBackend(dir string) (*Backend, error) {
	if err := openDir(dir); err != nil {
		return nil, fmt.Errorf("filestore: open credential store %s: %w", dir, err)
	}
	vdir := filepath.Join(dir, variantsSubdir)
	if err := openDir(vdir); err != nil {
		return nil, fmt.Errorf("filestore: open variant store %s: %w", vdir, err)
	}
	// The subtree's own directory entry has to be durable before anything is
	// written inside it: fsync of a file's parent does not make the parent's
	// creation durable in ITS parent.
	if err := fsyncDir(dir); err != nil {
		return nil, fmt.Errorf("filestore: durably create %s: %w", vdir, err)
	}
	return &Backend{dir: dir, vdir: vdir}, nil
}

// hexName validates a name and returns its file name. Backends are handed hex
// payloads, so this is a total check on the only thing a path is built from —
// no name that reaches the filesystem can contain a separator or a dot
// segment, whatever a caller above passed.
func hexName(name string) (string, error) {
	if len(name) != 64 {
		return "", fmt.Errorf("%w: %q is not a 64-character hex name", vcresolver.ErrInvalidArgument, name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("%w: %q is not lowercase hex", vcresolver.ErrInvalidArgument, name)
		}
	}
	return name + ".json", nil
}

func (b *Backend) projectionPath(bodyHex string) (string, error) {
	name, err := hexName(bodyHex)
	if err != nil {
		return "", err
	}
	return filepath.Join(b.dir, name), nil
}

func (b *Backend) variantDir(bodyHex string) (string, error) {
	if _, err := hexName(bodyHex); err != nil {
		return "", err
	}
	return filepath.Join(b.vdir, bodyHex), nil
}

func (b *Backend) variantPath(bodyHex, variantHex string) (string, error) {
	dir, err := b.variantDir(bodyHex)
	if err != nil {
		return "", err
	}
	name, err := hexName(variantHex)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// PutIfAbsent implements vcresolver.VariantBackend: temp + fsync + LINK.
//
// The link is what makes this create-only. Rename — the store's idiom
// everywhere else — silently REPLACES an existing entry, which is exactly the
// overwrite this layer exists to prevent: the write-once check above would
// compare against bytes that had already been destroyed. os.Link fails with
// EEXIST instead, so the decision about a taken name is always made with both
// versions still present.
func (b *Backend) PutIfAbsent(bodyHex, variantHex string, wire []byte) (bool, error) {
	path, err := b.variantPath(bodyHex, variantHex)
	if err != nil {
		return false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Fast path: an existing entry needs no temp file at all.
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("filestore: stat variant: %w", err)
	}
	if err := b.ensureVariantDir(bodyHex); err != nil {
		return false, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return false, fmt.Errorf("filestore: create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(wire); err != nil {
		tmp.Close()
		return false, fmt.Errorf("filestore: write variant: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, fmt.Errorf("filestore: sync variant: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("filestore: close variant: %w", err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return true, nil
		}
		return false, fmt.Errorf("filestore: link variant: %w", err)
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return false, fmt.Errorf("filestore: sync variant dir: %w", err)
	}
	return false, nil
}

// ensureVariantDir creates a body's variant directory durably.
//
// The parent fsync is the part that is easy to omit: fsyncing the variant FILE
// and its own directory does not make that directory's entry durable in
// variants/. A power loss there loses a write this store already acknowledged —
// the entire directory, not one file. openDir's own creations are exempt
// because they happen at boot, before anything is acknowledged.
func (b *Backend) ensureVariantDir(bodyHex string) error {
	dir, err := b.variantDir(bodyHex)
	if err != nil {
		return err
	}
	switch _, err := os.Stat(dir); {
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("filestore: stat variant dir: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("filestore: create variant dir: %w", err)
	}
	if err := fsyncDir(b.vdir); err != nil {
		return fmt.Errorf("filestore: durably create variant dir: %w", err)
	}
	return nil
}

// ReadVariant implements vcresolver.VariantBackend.
func (b *Backend) ReadVariant(bodyHex, variantHex string) ([]byte, error) {
	path, err := b.variantPath(bodyHex, variantHex)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	// The variant subtree is the witness, not the root: it can be removed or
	// unmounted while the root stays, and then every variant this store holds
	// would answer "never held" — a storage failure reported as a fact about
	// provenance. (A body's own directory being absent IS a real miss: that
	// body simply has no variants.)
	return b.readFile(path, "variant", b.vdir)
}

// readFile reads path, mapping absence to ErrNotFound — but only after proving
// the directory that WOULD hold it is still there. A deleted or unmounted
// store must not read as "this credential was never held".
func (b *Backend) readFile(path, what, witness string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if _, statErr := os.Stat(witness); statErr != nil {
			return nil, fmt.Errorf("filestore: credential store %s unavailable: %w", witness, statErr)
		}
		return nil, vcresolver.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: read %s: %w", what, err)
	}
	return data, nil
}

// ListVariantHexes implements vcresolver.VariantBackend.
func (b *Backend) ListVariantHexes(bodyHex, fromExclusive string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	dir, err := b.variantDir(bodyHex)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	des, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		// A body with no directory holds no variants — a normal answer. But
		// the SUBTREE being gone is storage damage, and answering "no
		// variants" for every body would tell a caller this node never held
		// evidence it is in fact losing.
		if _, statErr := os.Stat(b.vdir); statErr != nil {
			return nil, fmt.Errorf("filestore: variant store %s unavailable: %w", b.vdir, statErr)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: list variants: %w", err)
	}
	out := make([]string, 0, len(des))
	for _, de := range des {
		if h, ok := entryHex(de); ok && h > fromExclusive {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return page(out, limit), nil
}

// ReadProjection implements vcresolver.VariantBackend.
func (b *Backend) ReadProjection(bodyHex string) ([]byte, error) {
	path, err := b.projectionPath(bodyHex)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.readFile(path, "projection", b.dir)
}

// WriteProjection implements vcresolver.VariantBackend. Rename is correct here
// precisely where it is wrong for a variant: this slot is a derived pointer
// that MUST be replaceable, or the winner could never move.
func (b *Backend) WriteProjection(bodyHex string, wire []byte) error {
	path, err := b.projectionPath(bodyHex)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := writeAtomic(path, wire); err != nil {
		return fmt.Errorf("filestore: write projection: %w", err)
	}
	return nil
}

// ListBodyHexes implements vcresolver.VariantBackend: the union of bodies with
// a flat slot and bodies with a variant directory.
//
// The union is not tidiness. A crash between the two writes, or a body that
// only ever got variants, leaves a body present in just one of them — and a
// body missing from this enumeration reads to the service's forward index as
// having no successors, which is a false answer about provenance rather than a
// missing optimisation.
func (b *Backend) ListBodyHexes(fromExclusive string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	seen := map[string]bool{}
	flat, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, fmt.Errorf("filestore: list bodies: %w", err)
	}
	for _, de := range flat {
		if h, ok := entryHex(de); ok && h > fromExclusive {
			seen[h] = true
		}
	}
	vdirs, err := os.ReadDir(b.vdir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("filestore: list variant bodies: %w", err)
	}
	for _, de := range vdirs {
		if !de.IsDir() || de.Name() <= fromExclusive || !isHex64(de.Name()) {
			continue
		}
		// An empty directory is not a held body: a crash between mkdir and
		// link would otherwise enumerate a body with nothing in it.
		if entries, err := os.ReadDir(filepath.Join(b.vdir, de.Name())); err == nil {
			for _, e := range entries {
				if _, ok := entryHex(e); ok {
					seen[de.Name()] = true
					break
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return page(out, limit), nil
}

// entryHex returns a directory entry's hex name if it is a credential file.
// Anything else — a directory (the variants subtree, seen while listing the
// root), a temp file, a foreign name — is not ours to interpret.
func entryHex(de fs.DirEntry) (string, bool) {
	if de.IsDir() {
		return "", false
	}
	base, ok := strings.CutSuffix(de.Name(), ".json")
	if !ok || !isHex64(base) {
		return "", false
	}
	return base, true
}

func isHex64(s string) bool {
	_, err := hexName(s)
	return err == nil
}

func page(sorted []string, limit int) []string {
	if len(sorted) > limit {
		return sorted[:limit]
	}
	return sorted
}
