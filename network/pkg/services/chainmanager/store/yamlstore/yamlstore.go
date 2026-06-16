// Package yamlstore is the filesystem chainmanager store: SubscriptionStore and
// AllowListStore persisted as one YAML file per record under a root directory.
//
// Subscriptions live at {root}/subscriptions/{id}.yaml (id is a single safe path
// segment). Allow-lists live at a nested path that INCLUDES the registry —
// {root}/allowlists/{registry}/{accountType}/{accountID}/{resourcePath…}.yaml —
// because an AllowListStore carries no single-registry deployment context (unlike
// the didregistry yamlstore, which omits the registry); omitting it would collide
// two registries' identical accountType/accountID (slice-9 Codex Medium). Every
// DID-derived segment is safe-segment-validated before any path is built, so a
// crafted segment can never escape root.
//
// Writes are atomic (temp file + rename), so a reader never observes a
// half-written record, and Save is full-replacement (matching the store
// contracts). Reads distinguish absent from corrupt: an absent subscription is
// store.ErrNotFound and an absent allow-list is empty (default-distrust), but a
// present-yet-unparseable file is a real error, never silently collapsed to
// NotFound/empty — that would silently drop a subscription or trust config
// (slice-9 Codex Medium).
package yamlstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// ── Subscription store ────────────────────────────────────────────────────────

// SubscriptionStore persists subscriptions as {root}/subscriptions/{id}.yaml.
type SubscriptionStore struct {
	root string
}

var _ store.SubscriptionStore = (*SubscriptionStore)(nil)

// NewSubscriptionStore returns a SubscriptionStore rooted at dir.
func NewSubscriptionStore(dir string) *SubscriptionStore {
	return &SubscriptionStore{root: dir}
}

func (s *SubscriptionStore) subDir() string { return filepath.Join(s.root, "subscriptions") }

func (s *SubscriptionStore) path(id string) (string, error) {
	if err := safeSegment(id); err != nil {
		return "", err
	}
	return filepath.Join(s.subDir(), id+".yaml"), nil
}

func (s *SubscriptionStore) Save(sub *store.Subscription) error {
	p, err := s.path(sub.ID)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(toSubRecord(sub))
	if err != nil {
		return fmt.Errorf("yamlstore: marshal subscription: %w", err)
	}
	return atomicWrite(p, data)
}

func (s *SubscriptionStore) Get(id string) (*store.Subscription, error) {
	p, err := s.path(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("yamlstore: read subscription: %w", err)
	}
	var r subRecord
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yamlstore: corrupt subscription %q: %w", id, err)
	}
	return fromSubRecord(r), nil
}

func (s *SubscriptionStore) Delete(id string) error {
	p, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store.ErrNotFound
		}
		return fmt.Errorf("yamlstore: delete subscription: %w", err)
	}
	return nil
}

func (s *SubscriptionStore) List() ([]*store.Subscription, error) {
	entries, err := os.ReadDir(s.subDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yamlstore: list subscriptions: %w", err)
	}
	var out []*store.Subscription
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.subDir(), e.Name()))
		if err != nil {
			return nil, fmt.Errorf("yamlstore: read subscription %s: %w", e.Name(), err)
		}
		var r subRecord
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("yamlstore: corrupt subscription %s: %w", e.Name(), err)
		}
		out = append(out, fromSubRecord(r))
	}
	return out, nil
}

// ── Allow-list store ──────────────────────────────────────────────────────────

// AllowListStore persists per-pipeline allow-lists under {root}/allowlists/…,
// with the registry as the first path segment.
type AllowListStore struct {
	root string
}

var _ store.AllowListStore = (*AllowListStore)(nil)

// NewAllowListStore returns an AllowListStore rooted at dir.
func NewAllowListStore(dir string) *AllowListStore {
	return &AllowListStore{root: dir}
}

// path maps a pipeline DID to its allow-list file. The key must be a parseable
// dplaax pipeline DID; a non-pipeline or unparseable key is rejected, not
// silently pathed.
func (s *AllowListStore) path(pipelineDID string) (string, error) {
	d, err := dplaax.Parse(pipelineDID)
	if err != nil {
		return "", fmt.Errorf("yamlstore: %w", err)
	}
	if !d.IsPipeline() {
		return "", fmt.Errorf("yamlstore: %q is not a pipeline DID", pipelineDID)
	}
	segs := append([]string{d.Registry, d.AccountType, d.AccountID}, d.ResourcePath...)
	for _, seg := range segs {
		if err := safeSegment(seg); err != nil {
			return "", err
		}
	}
	return filepath.Join(append([]string{s.root, "allowlists"}, segs...)...) + ".yaml", nil
}

func (s *AllowListStore) Save(pipelineDID string, rules []store.AllowRule) error {
	p, err := s.path(pipelineDID)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(toAllowRecord(rules))
	if err != nil {
		return fmt.Errorf("yamlstore: marshal allow-list: %w", err)
	}
	return atomicWrite(p, data)
}

// Get returns the pipeline's rules. An absent allow-list is empty (nil, nil) —
// default-distrust — but a present-yet-corrupt file is a real error.
func (s *AllowListStore) Get(pipelineDID string) ([]store.AllowRule, error) {
	p, err := s.path(pipelineDID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yamlstore: read allow-list: %w", err)
	}
	var r allowRecord
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yamlstore: corrupt allow-list %q: %w", pipelineDID, err)
	}
	return fromAllowRecord(r), nil
}

// ── on-disk records ───────────────────────────────────────────────────────────

type subRecord struct {
	ID              string            `yaml:"id"`
	SubscriberDID   string            `yaml:"subscriberDID"`
	PublisherDID    string            `yaml:"publisherDID"`
	PublishType     string            `yaml:"publishType"`
	PayloadDelivery string            `yaml:"payloadDelivery"`
	ConnectionInfo  map[string]string `yaml:"connectionInfo,omitempty"`
	Created         time.Time         `yaml:"created"`
}

func toSubRecord(s *store.Subscription) subRecord {
	return subRecord{
		ID:              s.ID,
		SubscriberDID:   s.SubscriberDID,
		PublisherDID:    s.PublisherDID,
		PublishType:     s.PublishType,
		PayloadDelivery: s.PayloadDelivery,
		ConnectionInfo:  s.ConnectionInfo,
		Created:         s.Created,
	}
}

func fromSubRecord(r subRecord) *store.Subscription {
	return &store.Subscription{
		ID:              r.ID,
		SubscriberDID:   r.SubscriberDID,
		PublisherDID:    r.PublisherDID,
		PublishType:     r.PublishType,
		PayloadDelivery: r.PayloadDelivery,
		ConnectionInfo:  r.ConnectionInfo,
		Created:         r.Created,
	}
}

type allowRecord struct {
	Rules []ruleRecord `yaml:"rules"`
}

type ruleRecord struct {
	Pattern string `yaml:"pattern"`
}

func toAllowRecord(rules []store.AllowRule) allowRecord {
	rr := make([]ruleRecord, len(rules))
	for i, r := range rules {
		rr[i] = ruleRecord{Pattern: r.Pattern}
	}
	return allowRecord{Rules: rr}
}

func fromAllowRecord(r allowRecord) []store.AllowRule {
	if len(r.Rules) == 0 {
		return nil
	}
	out := make([]store.AllowRule, len(r.Rules))
	for i, rr := range r.Rules {
		out[i] = store.AllowRule{Pattern: rr.Pattern}
	}
	return out
}

// ── filesystem helpers ────────────────────────────────────────────────────────

// safeSegment rejects anything that is not a single, non-traversing path
// component (the traversal guard lives here, not in callers).
func safeSegment(s string) error {
	if s == "" || s == "." || s == ".." || s != filepath.Base(s) || strings.ContainsAny(s, `/\`+"\x00") {
		return fmt.Errorf("yamlstore: invalid path segment %q", s)
	}
	return nil
}

// atomicWrite publishes data at p via a temp file + rename (full replacement),
// creating parent directories as needed. A reader observes either the prior
// contents or the complete new contents, never a partial write. Power-loss
// durability of the parent directory entry is out of scope for this staged PoC
// substrate — the durable backend is the long-term target.
func atomicWrite(p string, data []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("yamlstore: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("yamlstore: temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("yamlstore: sync temp: %w", err)
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
