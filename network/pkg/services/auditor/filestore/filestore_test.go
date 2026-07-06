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
