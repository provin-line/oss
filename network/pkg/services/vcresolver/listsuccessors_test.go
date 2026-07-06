package vcresolver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// chainWire builds a minimal wire-form credential with processID (for hash
// distinctness) and an optional previousCredential link.
func chainWire(t *testing.T, processID, prev string) []byte {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": processID}
	if prev != "" {
		subject["previousCredential"] = prev
	}
	// canonicalizer-hygiene-exempt: test fixture bytes, re-canonicalized by StoreVC.
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newIndexedService(t *testing.T) *vcresolver.Service {
	t.Helper()
	return vcresolver.New(memstore.NewStore(), memstore.NewPool())
}

func mustStore(t *testing.T, s *vcresolver.Service, wire []byte) string {
	t.Helper()
	h, err := s.StoreVC(context.Background(), wire, "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	return h
}

func TestListSuccessors_ForwardTraversal(t *testing.T) {
	ctx := context.Background()
	s := newIndexedService(t)
	origin := mustStore(t, s, chainWire(t, "origin", ""))
	c1 := mustStore(t, s, chainWire(t, "childA", origin))
	c2 := mustStore(t, s, chainWire(t, "childB", origin))
	g1 := mustStore(t, s, chainWire(t, "grand", c1))

	got, more, err := s.ListSuccessors(ctx, origin, "", 10)
	if err != nil || more {
		t.Fatalf("ListSuccessors(origin): more=%v err=%v", more, err)
	}
	want := []string{c1, c2}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0] // lexicographic contract
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("successors(origin) = %v, want %v", got, want)
	}
	if got, _, err := s.ListSuccessors(ctx, c1, "", 10); err != nil || len(got) != 1 || got[0] != g1 {
		t.Fatalf("successors(c1) = %v (err %v), want [%s]", got, err, g1)
	}
	// Childless and unknown hashes are empty pages, never errors: "no known
	// successors" is a normal answer scoped to this node's store.
	if got, _, err := s.ListSuccessors(ctx, g1, "", 10); err != nil || len(got) != 0 {
		t.Fatalf("successors(leaf) = %v (err %v), want empty", got, err)
	}
	unknown := "sha256:" + strings.Repeat("77", 32)
	if got, _, err := s.ListSuccessors(ctx, unknown, "", 10); err != nil || len(got) != 0 {
		t.Fatalf("successors(unknown) = %v (err %v), want empty", got, err)
	}
}

func TestListSuccessors_Pagination(t *testing.T) {
	ctx := context.Background()
	s := newIndexedService(t)
	origin := mustStore(t, s, chainWire(t, "origin", ""))
	c1 := mustStore(t, s, chainWire(t, "childA", origin))
	c2 := mustStore(t, s, chainWire(t, "childB", origin))
	first, second := c1, c2
	if first > second {
		first, second = second, first
	}

	page1, more, err := s.ListSuccessors(ctx, origin, "", 1)
	if err != nil || !more || len(page1) != 1 || page1[0] != first {
		t.Fatalf("page1 = %v more=%v err=%v, want [%s] more=true", page1, more, err, first)
	}
	page2, more, err := s.ListSuccessors(ctx, origin, page1[0], 1)
	if err != nil || len(page2) != 1 || page2[0] != second {
		t.Fatalf("page2 = %v (err %v), want [%s]", page2, err, second)
	}
	if more {
		// Exactly limit entries remained: one extra empty page is legal.
		rest, more2, err := s.ListSuccessors(ctx, origin, page2[0], 1)
		if err != nil || len(rest) != 0 || more2 {
			t.Fatalf("exhausted page = %v more=%v err=%v, want empty/false", rest, more2, err)
		}
	}
}

func TestListSuccessors_IndexMaintainedAfterBuild(t *testing.T) {
	ctx := context.Background()
	s := newIndexedService(t)
	origin := mustStore(t, s, chainWire(t, "origin", ""))
	if got, _, err := s.ListSuccessors(ctx, origin, "", 10); err != nil || len(got) != 0 {
		t.Fatalf("pre-child successors = %v (err %v), want empty", got, err)
	}
	// The index is already materialized; a later StoreVC must land in it.
	c1 := mustStore(t, s, chainWire(t, "late-child", origin))
	got, _, err := s.ListSuccessors(ctx, origin, "", 10)
	if err != nil || len(got) != 1 || got[0] != c1 {
		t.Fatalf("post-child successors = %v (err %v), want [%s] — StoreVC must maintain the built index", got, err, c1)
	}
}

func TestListSuccessors_MalformedHash(t *testing.T) {
	s := newIndexedService(t)
	if _, _, err := s.ListSuccessors(context.Background(), "not-a-hash", "", 10); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Fatalf("malformed hash: err=%v, want ErrInvalidArgument", err)
	}
}

// damageStore wraps a Store, failing Get for one hash — the index build must
// hard-error, never build a silently incomplete index (false "no
// descendants" is the failure recall cannot tolerate).
type damageStore struct {
	vcresolver.Store
	damaged string
}

func (d damageStore) Get(hash string) (*vc.PipelinePassCredential, error) {
	if hash == d.damaged {
		return nil, errors.New("damaged credential entry")
	}
	return d.Store.Get(hash)
}

func TestListSuccessors_BuildHardErrorsOnDamage(t *testing.T) {
	ctx := context.Background()
	inner := memstore.NewStore()
	seed := vcresolver.New(inner, memstore.NewPool())
	origin := mustStore(t, seed, chainWire(t, "origin", ""))
	child := mustStore(t, seed, chainWire(t, "child", origin))

	s := vcresolver.New(damageStore{Store: inner, damaged: child}, memstore.NewPool())
	if _, _, err := s.ListSuccessors(ctx, origin, "", 10); err == nil {
		t.Fatal("index build over a damaged store: want error, got a (possibly incomplete) listing")
	}
}

// A stored credential whose previousCredential is a string but NOT a content
// address is store damage: indexing it under the invalid key would make it
// invisible (ListSuccessors rejects malformed query hashes) — the build must
// fail loudly instead (Codex P2).
func TestListSuccessors_BuildRejectsMalformedLink(t *testing.T) {
	ctx := context.Background()
	inner := memstore.NewStore()
	var cred vc.PipelinePassCredential
	// decoder-hygiene-exempt: test fixture from bytes this test just built.
	if err := json.Unmarshal(chainWire(t, "bad", "not-a-content-address"), &cred); err != nil {
		t.Fatal(err)
	}
	h, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if err := inner.Put(h, &cred); err != nil { // bypasses StoreVC validation, as tampering would
		t.Fatal(err)
	}
	s := vcresolver.New(inner, memstore.NewPool())
	if _, _, err := s.ListSuccessors(ctx, h, "", 10); err == nil || !strings.Contains(err.Error(), "not a sha256") {
		t.Fatalf("malformed stored link: err=%v, want loud build failure", err)
	}
}

// N writers racing the first index build and subsequent reads: the
// documented interleaving argument, enforced under -race.
func TestListSuccessors_ConcurrentStoreAndList(t *testing.T) {
	ctx := context.Background()
	s := newIndexedService(t)
	origin := mustStore(t, s, chainWire(t, "origin", ""))

	const writers = 8
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.StoreVC(ctx, chainWire(t, fmt.Sprintf("w%02d", i), origin), "", 0); err != nil {
				t.Errorf("StoreVC: %v", err)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if _, _, err := s.ListSuccessors(ctx, origin, "", 100); err != nil {
				t.Errorf("ListSuccessors: %v", err)
				return
			}
		}
	}()
	wg.Wait()
	<-done
	got, _, err := s.ListSuccessors(ctx, origin, "", 100)
	if err != nil || len(got) != writers {
		t.Fatalf("final successors = %d (err %v), want %d — every raced write must land in the index", len(got), err, writers)
	}
}
