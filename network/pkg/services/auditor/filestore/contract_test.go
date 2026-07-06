package filestore_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	"github.com/provin-line/oss/network/pkg/services/auditor/internal/storecontract"
)

// The shared behavioral contract, run against the file implementations — the
// mem siblings run the SAME suite, so semantics cannot drift apart silently.
func TestContract_StatusStore(t *testing.T) {
	storecontract.StatusStore(t, func(t *testing.T) auditor.StatusStore {
		s, err := filestore.NewStatusStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestContract_ReceiptStore(t *testing.T) {
	storecontract.ReceiptStore(t, func(t *testing.T) auditor.ReceiptStore {
		s, err := filestore.NewReceiptStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestContract_Queue(t *testing.T) {
	storecontract.Queue(t, func(t *testing.T) auditor.AuditQueue {
		q, err := filestore.NewQueue(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return q
	})
}

// Invalid keys fail closed on every entry point (the vcresolver twin has the
// same pin).
func TestInvalidKeysFailClosed(t *testing.T) {
	s, err := filestore.NewStatusStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"", "h1", "sha256:xyz", "../../etc/passwd"} {
		if err := s.Put(k, storecontract.Record()); err == nil {
			t.Errorf("StatusStore.Put(%q): want error", k)
		}
		if _, err := s.Get(k); err == nil {
			t.Errorf("StatusStore.Get(%q): want error", k)
		}
	}
	q, err := filestore.NewQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Add("not-a-hash"); err == nil {
		t.Error("Queue.Add(invalid): want error")
	}
}
