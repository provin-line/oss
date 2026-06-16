// Package yamlstore is the filesystem DIDStore: the did:dplaax hierarchy maps
// to a directory tree and each DID node holds its document, delegation, status,
// and append-only lifecycle log as files.
//
// Layout (registry is the store's deployment context — one registry per store —
// so it is not part of the path; the service enforces the registry-segment
// binding, D-d8):
//
//	{accountType}/{accountId}/                      ← owner node
//	    document.json                               ← DID Document (canonical JSON)
//	    status.yaml
//	    lifecycle/000000.yaml ...                   ← append-only events
//	    pipelines/{id}/                             ← pipeline node
//	        document.json delegation.json status.yaml lifecycle/...
//	        processes/{id}/                         ← process node
//	            document.json delegation.json status.yaml lifecycle/...
//
// Every DID-derived segment is validated to a single safe path component before
// any path is built, so a crafted segment can never escape root (the traversal
// guard lives here, not in callers). The store holds no validation or hash-chain
// logic: Save creates documents with O_EXCL (a re-register is ErrExists), status
// flips through atomic temp+rename, and lifecycle events are per-event O_EXCL
// files appended in order — so the yamlstore→tlog swap is implementation-only.
package yamlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
)

const (
	documentFile   = "document.json"
	delegationFile = "delegation.json"
	statusFile     = "status.yaml"
	lifecycleDir   = "lifecycle"
)

// Store persists DID nodes as a directory tree under root.
type Store struct {
	root string
}

var _ store.DIDStore = (*Store)(nil)

// New returns a Store rooted at dir.
func New(dir string) *Store {
	return &Store{root: dir}
}

// statusRecord is the on-disk status shape.
type statusRecord struct {
	Status string `yaml:"status"`
}

// eventRecord is the on-disk lifecycle-event shape. OutwardSnapshot is []byte so
// an opaque outward document round-trips faithfully (YAML base64-encodes it).
type eventRecord struct {
	EventType       string    `yaml:"eventType"`
	DIDDocSnapshot  string    `yaml:"didDocSnapshot"`
	OutwardSnapshot []byte    `yaml:"outwardSnapshot,omitempty"`
	WitnessSource   string    `yaml:"witnessSource"`
	WitnessedAt     time.Time `yaml:"witnessedAt"`
	PrevEventHash   string    `yaml:"prevEventHash,omitempty"`
}

// nodeDir builds the directory for d from validated segments. The fixed
// "pipelines"/"processes" literals partition the namespace so a pipeline id can
// never collide with the reserved words.
func (s *Store) nodeDir(d *dplaax.DID) (string, error) {
	if d == nil {
		return "", fmt.Errorf("yamlstore: nil DID")
	}
	for _, seg := range append([]string{d.AccountType, d.AccountID}, d.ResourcePath...) {
		if err := safeSegment(seg); err != nil {
			return "", err
		}
	}
	switch {
	case d.IsOwner():
		return filepath.Join(s.root, d.AccountType, d.AccountID), nil
	case d.IsPipeline():
		return filepath.Join(s.root, d.AccountType, d.AccountID, "pipelines", d.ResourcePath[1]), nil
	case d.IsProcess():
		return filepath.Join(s.root, d.AccountType, d.AccountID, "pipelines", d.ResourcePath[1], "processes", d.ResourcePath[3]), nil
	default:
		return "", fmt.Errorf("yamlstore: unsupported DID shape %q", d.String())
	}
}

// safeSegment rejects anything that is not a single, non-traversing path
// component.
func safeSegment(s string) error {
	if s == "" || s == "." || s == ".." || s != filepath.Base(s) || strings.ContainsAny(s, `/\`+"\x00") {
		return fmt.Errorf("yamlstore: invalid path segment %q", s)
	}
	return nil
}

func (s *Store) SaveOwner(d *dplaax.DID, doc *did.DIDDocument) error {
	if !d.IsOwner() {
		return fmt.Errorf("yamlstore: SaveOwner: %q is not an owner DID", d.String())
	}
	return s.saveNode(d, doc, nil)
}

func (s *Store) SavePipeline(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error {
	if !d.IsPipeline() {
		return fmt.Errorf("yamlstore: SavePipeline: %q is not a pipeline DID", d.String())
	}
	return s.saveNode(d, doc, dlg)
}

func (s *Store) SaveProcess(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error {
	if !d.IsProcess() {
		return fmt.Errorf("yamlstore: SaveProcess: %q is not a process DID", d.String())
	}
	return s.saveNode(d, doc, dlg)
}

// saveNode writes the document (O_EXCL — a re-save is ErrExists), the optional
// delegation, and the initial active status. The document is the existence
// marker: it is created exclusively first, so a partially-written node is never
// published and a duplicate registration fails before any other file is touched.
func (s *Store) saveNode(d *dplaax.DID, doc *did.DIDDocument, dlg *delegation.DelegationCredential) error {
	dir, err := s.nodeDir(d)
	if err != nil {
		return err
	}
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("yamlstore: marshal document: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("yamlstore: mkdir: %w", err)
	}
	if err := createExclusive(filepath.Join(dir, documentFile), docBytes); err != nil {
		return err
	}
	if dlg != nil {
		dlgBytes, err := json.Marshal(dlg)
		if err != nil {
			return fmt.Errorf("yamlstore: marshal delegation: %w", err)
		}
		if err := atomicWrite(filepath.Join(dir, delegationFile), dlgBytes); err != nil {
			return err
		}
	}
	return s.writeStatus(dir, store.StatusActive)
}

func (s *Store) Resolve(d *dplaax.DID) (*did.DIDDocument, error) {
	dir, err := s.nodeDir(d)
	if err != nil {
		return nil, err
	}
	data, err := readFile(filepath.Join(dir, documentFile))
	if err != nil {
		return nil, err
	}
	var doc did.DIDDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("yamlstore: unmarshal document: %w", err)
	}
	return &doc, nil
}

func (s *Store) ResolveDelegation(d *dplaax.DID) (*delegation.DelegationCredential, error) {
	dir, err := s.nodeDir(d)
	if err != nil {
		return nil, err
	}
	data, err := readFile(filepath.Join(dir, delegationFile))
	if err != nil {
		return nil, err
	}
	var dlg delegation.DelegationCredential
	if err := json.Unmarshal(data, &dlg); err != nil {
		return nil, fmt.Errorf("yamlstore: unmarshal delegation: %w", err)
	}
	return &dlg, nil
}

// UpdateStatus flips the status flag atomically. The node must exist (its
// document is the existence marker) — updating an absent DID is ErrNotFound.
func (s *Store) UpdateStatus(d *dplaax.DID, status store.DIDStatus) error {
	dir, err := s.nodeDir(d)
	if err != nil {
		return err
	}
	if _, err := readFile(filepath.Join(dir, documentFile)); err != nil {
		return err // ErrNotFound when the node does not exist
	}
	return s.writeStatus(dir, status)
}

func (s *Store) GetStatus(d *dplaax.DID) (store.DIDStatus, error) {
	dir, err := s.nodeDir(d)
	if err != nil {
		return "", err
	}
	return readStatus(dir)
}

func (s *Store) ListPipelines(owner *dplaax.DID) ([]store.DIDSummary, error) {
	if !owner.IsOwner() {
		return nil, fmt.Errorf("yamlstore: ListPipelines: %q is not an owner DID", owner.String())
	}
	dir, err := s.nodeDir(owner)
	if err != nil {
		return nil, err
	}
	return s.listChildren(filepath.Join(dir, "pipelines"), func(id string) *dplaax.DID {
		c := *owner
		c.ResourcePath = []string{"pipeline", id}
		return &c
	})
}

func (s *Store) ListProcesses(pipeline *dplaax.DID) ([]store.DIDSummary, error) {
	if !pipeline.IsPipeline() {
		return nil, fmt.Errorf("yamlstore: ListProcesses: %q is not a pipeline DID", pipeline.String())
	}
	dir, err := s.nodeDir(pipeline)
	if err != nil {
		return nil, err
	}
	return s.listChildren(filepath.Join(dir, "processes"), func(id string) *dplaax.DID {
		c := *pipeline
		c.ResourcePath = append(append([]string(nil), pipeline.ResourcePath...), "process", id)
		return &c
	})
}

// listChildren enumerates the child node directories under parent and resolves
// each child's DID (via childDID) and status. A missing parent dir yields an
// empty list, not an error.
func (s *Store) listChildren(parent string, childDID func(id string) *dplaax.DID) ([]store.DIDSummary, error) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yamlstore: readdir: %w", err)
	}
	var out []store.DIDSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		status, err := readStatus(filepath.Join(parent, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("yamlstore: list %s: %w", e.Name(), err)
		}
		out = append(out, store.DIDSummary{DID: childDID(e.Name()).String(), Status: status})
	}
	return out, nil
}

// AppendLifecycleEvent writes ev as the next per-event file under the node's
// lifecycle dir. The sequence is the count of existing events; a concurrent
// append that grabbed the same index loses the O_EXCL race, so the writer
// advances to the next free slot. The store never rewrites or deletes an entry.
func (s *Store) AppendLifecycleEvent(d *dplaax.DID, ev store.LifecycleEvent) error {
	dir, err := s.nodeDir(d)
	if err != nil {
		return err
	}
	logDir := filepath.Join(dir, lifecycleDir)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("yamlstore: mkdir lifecycle: %w", err)
	}
	data, err := yaml.Marshal(toEventRecord(ev))
	if err != nil {
		return fmt.Errorf("yamlstore: marshal event: %w", err)
	}
	seq, err := s.eventCount(logDir)
	if err != nil {
		return err
	}
	// Advance past any concurrently-claimed slots; the bound is generous and
	// only guards against a live race, not unbounded contention.
	for i := 0; i < 1024; i++ {
		err := createExclusive(filepath.Join(logDir, eventFileName(seq+i)), data)
		if err == nil {
			return nil
		}
		if !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	return fmt.Errorf("yamlstore: lifecycle append: no free slot after %d attempts", 1024)
}

func (s *Store) ReadLifecycleLog(d *dplaax.DID) ([]store.LifecycleEvent, error) {
	dir, err := s.nodeDir(d)
	if err != nil {
		return nil, err
	}
	logDir := filepath.Join(dir, lifecycleDir)
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yamlstore: readdir lifecycle: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	// Zero-padded names sort lexically into append order.
	sort.Strings(names)
	out := make([]store.LifecycleEvent, 0, len(names))
	for _, name := range names {
		data, err := readFile(filepath.Join(logDir, name))
		if err != nil {
			return nil, fmt.Errorf("yamlstore: read event %s: %w", name, err)
		}
		var r eventRecord
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("yamlstore: unmarshal event %s: %w", name, err)
		}
		out = append(out, fromEventRecord(r))
	}
	return out, nil
}

func (s *Store) eventCount(logDir string) (int, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("yamlstore: count events: %w", err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			n++
		}
	}
	return n, nil
}

func eventFileName(seq int) string { return fmt.Sprintf("%06d.yaml", seq) }

func (s *Store) writeStatus(dir string, status store.DIDStatus) error {
	data, err := yaml.Marshal(statusRecord{Status: string(status)})
	if err != nil {
		return fmt.Errorf("yamlstore: marshal status: %w", err)
	}
	return atomicWrite(filepath.Join(dir, statusFile), data)
}

func readStatus(dir string) (store.DIDStatus, error) {
	data, err := readFile(filepath.Join(dir, statusFile))
	if err != nil {
		return "", err
	}
	var r statusRecord
	if err := yaml.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("yamlstore: unmarshal status: %w", err)
	}
	return store.DIDStatus(r.Status), nil
}

func toEventRecord(ev store.LifecycleEvent) eventRecord {
	return eventRecord{
		EventType:       ev.EventType,
		DIDDocSnapshot:  ev.DIDDocSnapshot,
		OutwardSnapshot: ev.OutwardSnapshot,
		WitnessSource:   ev.WitnessSource,
		WitnessedAt:     ev.WitnessedAt,
		PrevEventHash:   ev.PrevEventHash,
	}
}

func fromEventRecord(r eventRecord) store.LifecycleEvent {
	return store.LifecycleEvent{
		EventType:       r.EventType,
		DIDDocSnapshot:  r.DIDDocSnapshot,
		OutwardSnapshot: r.OutwardSnapshot,
		WitnessSource:   r.WitnessSource,
		WitnessedAt:     r.WitnessedAt,
		PrevEventHash:   r.PrevEventHash,
	}
}

func readFile(p string) ([]byte, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("yamlstore: read: %w", err)
	}
	return data, nil
}

// createExclusive publishes data at p only if p does not already exist: the
// record is written to a temp file in the same dir and linked into place, so a
// reader never sees a partial file and a collision returns store.ErrExists.
func createExclusive(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("yamlstore: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // link shares the inode; removing the temp name keeps p.
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("yamlstore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("yamlstore: close temp: %w", err)
	}
	if err := os.Link(tmpName, p); err != nil {
		if errors.Is(err, os.ErrExist) {
			return store.ErrExists
		}
		return fmt.Errorf("yamlstore: publish: %w", err)
	}
	return nil
}

func atomicWrite(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("yamlstore: temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: close temp: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: rename: %w", err)
	}
	return nil
}
