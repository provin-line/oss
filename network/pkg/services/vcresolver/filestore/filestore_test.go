package filestore_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/vc"
)

// cred builds a minimal wire-form credential (optionally chained to prev).
func cred(t *testing.T, prev string) *vc.PipelinePassCredential {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "s1"}
	if prev != "" {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func credHash(t *testing.T, c *vc.PipelinePassCredential) string {
	t.Helper()
	h, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func poolHash(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

func TestPool_UpsertOrderingRestart(t *testing.T) {
	dir := t.TempDir()
	p, err := filestore.NewPool(dir)
	if err != nil {
		t.Fatal(err)
	}
	h1, h2 := poolHash(1), poolHash(2)
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, ReferrerIssuer: "did:a", AssemblyDepth: 3}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h2, UpstreamEndpoint: "https://u2", AssemblyDepth: 1}); err != nil {
		t.Fatal(err)
	}
	if p.Len() != 2 {
		t.Fatalf("len = %d, want 2", p.Len())
	}
	list, err := p.ListNewest(10)
	if err != nil || len(list) != 2 || list[0].Hash != h2 || list[1].Hash != h1 {
		t.Fatalf("order = %+v (err %v)", list, err)
	}

	// Upsert: fills empty hint, keeps non-empty, keeps min depth, no dup.
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, UpstreamEndpoint: "https://u1", AssemblyDepth: 2}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, ReferrerIssuer: "", AssemblyDepth: 5}); err != nil {
		t.Fatal(err)
	}
	e, ok := p.Get(h1)
	if !ok || e.UpstreamEndpoint != "https://u1" || e.ReferrerIssuer != "did:a" || e.AssemblyDepth != 2 {
		t.Fatalf("upsert-merge wrong: %+v ok=%v", e, ok)
	}
	if p.Len() != 2 {
		t.Fatalf("upsert duplicated: len = %d", p.Len())
	}

	if err := p.IncrementRetry(h1); err != nil {
		t.Fatal(err)
	}

	// Restart: a fresh instance sees entries, order, retry counts; new adds
	// keep sorting newer than survivors.
	p2, err := filestore.NewPool(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok = p2.Get(h1)
	if !ok || e.RetryCount != 1 || e.AssemblyDepth != 2 {
		t.Fatalf("post-restart entry = %+v ok=%v", e, ok)
	}
	h3 := poolHash(3)
	if err := p2.Add(vcresolver.UnresolvedEntry{Hash: h3, AssemblyDepth: 1}); err != nil {
		t.Fatal(err)
	}
	list, err = p2.ListNewest(1)
	if err != nil || len(list) != 1 || list[0].Hash != h3 {
		t.Fatalf("post-restart newest = %+v (err %v), want %s", list, err, h3)
	}
	if !p2.Has(h2) {
		t.Error("Has(h2) = false after restart")
	}
}

func TestPool_DepthAndMisses(t *testing.T) {
	p, err := filestore.NewPool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: poolHash(4), AssemblyDepth: 0}); err == nil {
		t.Error("AssemblyDepth 0: want error")
	}
	if err := p.Remove(poolHash(5)); err != nil {
		t.Errorf("Remove absent: want no-op, got %v", err)
	}
	if err := p.IncrementRetry(poolHash(6)); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("IncrementRetry absent: want ErrNotFound, got %v", err)
	}
	if _, ok := p.Get(poolHash(7)); ok {
		t.Error("Get absent: want ok=false")
	}
	if p.Has(poolHash(8)) {
		t.Error("Has absent: want false")
	}
}

// A damaged pool entry is working state: skipped (with a warning) by
// ListNewest, absent from Get, still counted by Has/Len, repaired by Add.
func TestPool_DamagedEntryIsSkippedAndRepaired(t *testing.T) {
	dir := t.TempDir()
	p, err := filestore.NewPool(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := poolHash(9)
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h, AssemblyDepth: 2}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(h, "sha256:")+".json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListNewest(10)
	if err != nil || len(list) != 0 {
		t.Fatalf("damaged entry in list = %+v (err %v), want skipped", list, err)
	}
	if _, ok := p.Get(h); ok {
		t.Error("damaged Get: want absent")
	}
	if !p.Has(h) {
		t.Error("damaged Has: want true (still queued until repaired)")
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h, AssemblyDepth: 4}); err != nil {
		t.Fatalf("repair Add: %v", err)
	}
	if e, ok := p.Get(h); !ok || e.AssemblyDepth != 4 {
		t.Fatalf("repaired entry = %+v ok=%v", e, ok)
	}
}
