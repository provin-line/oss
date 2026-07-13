package merklelog

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// Fault injection (white-box): closing the journal fd out from under the log
// makes the next Append's write fail AND its rollback truncate fail — the
// poison path. A poisoned log refuses every later append.
func TestAppendFailureRollbackFailurePoisons(t *testing.T) {
	l, err := New(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	l.file.Close() // sever the fd: write fails, rollback truncate fails
	if _, err := l.Append(context.Background(), []byte("beta")); err == nil {
		t.Fatal("append over a severed fd: want error")
	}
	if !l.broken {
		t.Fatal("rollback failure must poison the log")
	}
	if _, err := l.Append(context.Background(), []byte("gamma")); err == nil || !strings.Contains(err.Error(), "poisoned") {
		t.Fatalf("append on a poisoned log = %v, want poisoned refusal", err)
	}
}
