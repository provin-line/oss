package filestore_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	"github.com/provin-line/oss/vc"
)

func h(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

func entryPath(dir, hash string) string {
	return filepath.Join(dir, strings.TrimPrefix(hash, "sha256:")+".json")
}

func verifiedRecord() auditor.AuditRecord {
	v := vc.ConfidenceVerified
	return auditor.AuditRecord{
		Overall:   v,
		Axes:      vc.AxisResult{DataIntegrity: v, SignerAuthenticity: v, ChainConsistency: v},
		Notations: []string{"n1"},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
}

func TestStatusStore_RoundTripRestartOverwrite(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := verifiedRecord()
	if err := s.Put(h(1), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h(1))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("roundtrip mismatch:\n got = %+v\nwant = %+v", got, rec)
	}

	// Restart: a fresh instance over the same dir serves the verdict.
	s2, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Get(h(1)); err != nil || !reflect.DeepEqual(got, rec) {
		t.Fatalf("post-restart Get = %+v (err %v)", got, err)
	}

	// Latest audit wins.
	rec2 := rec
	rec2.Overall = vc.ConfidenceFailed
	if err := s2.Put(h(1), rec2); err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Get(h(1)); got.Overall != vc.ConfidenceFailed {
		t.Fatalf("overwrite: got %v, want Failed", got.Overall)
	}
}

// The abandon lifecycle marker survives the disk round-trip — losing it on
// restart would resurrect the "retrying or gave up?" ambiguity it exists to kill.
func TestStatusStore_AbandonedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	i := vc.ConfidenceIndeterminate
	rec := auditor.AuditRecord{
		Overall:   i,
		Axes:      vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i},
		Notations: []string{"audit abandoned: exhausted 3 attempts (head unreadable)"},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
		Abandoned: true,
	}
	if err := s.Put(h(2), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h(2))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("roundtrip mismatch:\n got = %+v\nwant = %+v", got, rec)
	}
}

// The RESOLUTION-outcome marker (AuditRecord.Unresolvable) survives the disk
// round-trip too — this is the P1-B fix: verdictEnvelope previously had no
// field for it, so Put silently dropped it and every restarted (or simply
// file-store-backed) node served CONFIDENCE_INDETERMINATE for a head the
// runner had actually given up resolving, never CONFIDENCE_UNRESOLVABLE.
func TestStatusStore_UnresolvableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	i := vc.ConfidenceIndeterminate
	rec := auditor.AuditRecord{
		Overall:      i,
		Axes:         vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i},
		Notations:    []string{"audit abandoned: exhausted 2 attempts (head not resolvable)"},
		Scope:        auditor.AuditScope{LinearChain: true},
		AuditedAt:    time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC),
		Abandoned:    true,
		Unresolvable: true,
	}
	if err := s.Put(h(11), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h(11))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("roundtrip mismatch:\n got = %+v\nwant = %+v", got, rec)
	}

	// Restart: a fresh instance over the same dir must still serve Unresolvable —
	// proving it is durably on disk, not merely surviving within one process.
	s2, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Get(h(11)); err != nil || !got.Unresolvable {
		t.Fatalf("post-restart Get = %+v (err %v), want Unresolvable=true", got, err)
	}
}

func TestStatusStore_AbsentAndDamaged(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(h(2)); !errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	if err := s.Put(h(2), verifiedRecord()); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"malformed":     "{broken",
		"wrong version": `{"v":2,"overall":2,"data_integrity":2,"signer_authenticity":2,"chain_consistency":2,"source_commitment":0,"linear_chain":true,"source_commitment_evaluated":false,"audited_at":"2026-07-06T12:00:00Z"}`,
		"zero time":     `{"v":1,"overall":2,"data_integrity":2,"signer_authenticity":2,"chain_consistency":2,"source_commitment":0,"linear_chain":true,"source_commitment_evaluated":false,"audited_at":"0001-01-01T00:00:00Z"}`,
		"enum range":    `{"v":1,"overall":9,"data_integrity":2,"signer_authenticity":2,"chain_consistency":2,"source_commitment":0,"linear_chain":true,"source_commitment_evaluated":false,"audited_at":"2026-07-06T12:00:00Z"}`,
		"scope breach":  `{"v":1,"overall":2,"data_integrity":2,"signer_authenticity":2,"chain_consistency":2,"source_commitment":2,"linear_chain":true,"source_commitment_evaluated":false,"audited_at":"2026-07-06T12:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(entryPath(dir, h(2)), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := s.Get(h(2))
			if err == nil || errors.Is(err, auditor.ErrNotFound) {
				t.Fatalf("%s: want damaged-entry error (not absence), got %v", name, err)
			}
		})
	}
}

func TestReceiptStore_RoundTripRestartDamaged(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(h(3)); !errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	consumed := []string{h(4), h(5)}
	if err := s.Put(h(3), consumed); err != nil {
		t.Fatal(err)
	}
	// The stored copy must not alias the caller's slice.
	consumed[0] = "clobbered"

	s2, err := filestore.NewReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(h(3))
	if err != nil || len(got) != 2 || got[0] != h(4) || got[1] != h(5) {
		t.Fatalf("post-restart receipt = %v (err %v)", got, err)
	}

	if err := os.WriteFile(entryPath(dir, h(3)), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get(h(3)); err == nil || errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("damaged receipt: want error distinct from absence, got %v", err)
	}
}

// The frozen contract (D1): Put canonicalizes (sort, dedup) and is first-write-wins. A
// canonically-identical replay (including a permuted one) is an idempotent no-op — this is
// what makes aggregate re-emit retries safe. A canonically-different Put is a conflict: the
// recorded set is pinned by the first successful write and never silently changes, and the
// pin survives a restarted store instance over the same directory.
func TestReceiptStore_CanonicalizationAndFirstWriteWins(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	head := h(20)

	// Unsorted + duplicated input canonicalizes to a sorted, deduped stored set.
	if err := s.Put(head, []string{h(3), h(2), h(2)}); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	want := []string{h(2), h(3)}
	if got, err := s.Get(head); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after canonicalizing Put = %v (err %v), want %v", got, err, want)
	}

	// Identical replay (same canonical form) is a no-op.
	if err := s.Put(head, []string{h(2), h(3)}); err != nil {
		t.Fatalf("identical replay: want nil, got %v", err)
	}

	// Permuted-but-equal (canonicalizes to the same set) is also a no-op.
	if err := s.Put(head, []string{h(3), h(2)}); err != nil {
		t.Fatalf("permuted-but-equal replay: want nil, got %v", err)
	}
	if got, _ := s.Get(head); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after replays = %v, want unchanged %v", got, want)
	}

	// A restarted store instance over the same dir still enforces the pinned set: a
	// different canonical set is a conflict, never an overwrite.
	s2, err := filestore.NewReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Put(head, []string{h(4)}); !errors.Is(err, auditor.ErrReceiptConflict) {
		t.Fatalf("different set after restart: want ErrReceiptConflict, got %v", err)
	}
	if got, _ := s2.Get(head); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after rejected conflicting Put = %v, want unchanged %v", got, want)
	}
}

// The canonicalizer enforces the content-address grammar per member (sha256:<64hex>) — a
// malformed member must never pin an irreversible first-write-wins receipt that every reader
// (GetConsumedSources, the source-commitment auditor) would then treat as damaged, and a
// "\n"-bearing member would otherwise let two DIFFERENT consumed sets collide under the same
// "\n"-joined signed view (the wireauth handler's deterministic join over the canonical set).
func TestReceiptStore_PutValidation(t *testing.T) {
	tests := []struct {
		name string
		in   []string
	}{
		{"empty set", []string{}},
		{"nil set", nil},
		{"empty-string member", []string{h(3), ""}},
		{"non-address member", []string{h(3), "not-a-content-hash"}},
		{"newline-bearing member", []string{h(3), h(4) + "\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := filestore.NewReceiptStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Put(h(9), tt.in); err == nil {
				t.Fatalf("Put(%v): want error", tt.in)
			}
		})
	}
}

// A damaged existing entry must fail closed on a later Put: it must not be silently treated as
// "no receipt" (which would let ANY Put — matching or not — through as a first write over
// damage) and must not be misreported as ErrReceiptConflict (which would say "content differs"
// about an entry whose content is unknown). The damage itself must surface.
func TestReceiptStore_PutOverDamagedEntryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewReceiptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	head := h(30)
	if err := os.WriteFile(entryPath(dir, head), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(head, []string{h(3)}); err == nil {
		t.Fatalf("Put over a damaged entry: want error, got nil")
	} else if errors.Is(err, auditor.ErrReceiptConflict) {
		t.Fatalf("Put over a damaged entry: want a damage error, not ErrReceiptConflict (got %v)", err)
	}
}

func TestQueue_DedupAttemptsOrderingRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := filestore.NewQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Add(h(6)); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(h(7)); err != nil {
		t.Fatal(err)
	}
	if err := q.IncrementAttempt(h(6)); err != nil {
		t.Fatal(err)
	}
	// Re-add preserves attempts and position.
	if err := q.Add(h(6)); err != nil {
		t.Fatal(err)
	}
	list, err := q.ListNewest(10)
	if err != nil || len(list) != 2 || list[0].HeadHash != h(7) || list[1].HeadHash != h(6) || list[1].Attempts != 1 {
		t.Fatalf("list = %+v (err %v)", list, err)
	}

	// Restart preserves entries, attempts, and ordering; new adds sort newest.
	q2, err := filestore.NewQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q2.Add(h(8)); err != nil {
		t.Fatal(err)
	}
	list, err = q2.ListNewest(1)
	if err != nil || len(list) != 1 || list[0].HeadHash != h(8) {
		t.Fatalf("post-restart newest = %+v (err %v)", list, err)
	}
	if q2.Len() != 3 {
		t.Fatalf("post-restart len = %d, want 3", q2.Len())
	}

	if err := q2.Remove(h(9)); err != nil {
		t.Errorf("Remove absent: want no-op, got %v", err)
	}
	if err := q2.IncrementAttempt(h(9)); !errors.Is(err, auditor.ErrNotQueued) {
		t.Errorf("IncrementAttempt absent: want ErrNotQueued, got %v", err)
	}
}

func TestQueue_DamagedEntrySkippedAndRepaired(t *testing.T) {
	dir := t.TempDir()
	q, err := filestore.NewQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Add(h(10)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath(dir, h(10)), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := q.ListNewest(10)
	if err != nil || len(list) != 0 {
		t.Fatalf("damaged entry in list = %+v (err %v), want skipped", list, err)
	}
	if q.Len() != 1 {
		t.Fatalf("len = %d, want 1 (damaged entry still occupies the queue)", q.Len())
	}
	if err := q.Add(h(10)); err != nil {
		t.Fatalf("repair Add: %v", err)
	}
	list, err = q.ListNewest(10)
	if err != nil || len(list) != 1 || list[0].HeadHash != h(10) || list[0].Attempts != 0 {
		t.Fatalf("repaired list = %+v (err %v)", list, err)
	}
}

// One damaged verdict entry must not deny enumeration: it lists as Damaged
// and everything sorting after it still lists intact (discovery-layer
// doctrine: damage visible, never absence, never a listing-wide error).
func TestStatusStoreList_DamagedEntryStaysEnumerable(t *testing.T) {
	dir := t.TempDir()
	s, err := filestore.NewStatusStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h1 := "sha256:" + strings.Repeat("11", 32)
	h2 := "sha256:" + strings.Repeat("22", 32)
	h3 := "sha256:" + strings.Repeat("33", 32)
	for _, h := range []string{h1, h2, h3} {
		if err := s.Put(h, verifiedRecord()); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt the middle entry on disk.
	if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(h2, "sha256:")+".json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := s.List("", 10)
	if err != nil {
		t.Fatalf("List with a damaged entry must not error the listing: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d entries, want 3", len(got))
	}
	if got[0].Head != h1 || got[0].Damaged {
		t.Errorf("entry[0] = %+v, want intact %s", got[0], h1)
	}
	if got[1].Head != h2 || !got[1].Damaged {
		t.Errorf("entry[1] = %+v, want DAMAGED %s", got[1], h2)
	}
	if got[2].Head != h3 || got[2].Damaged {
		t.Errorf("entry[2] = %+v, want intact %s (a damaged predecessor must not hide it)", got[2], h3)
	}
}
