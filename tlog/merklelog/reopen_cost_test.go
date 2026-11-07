package merklelog_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/provin-line/oss/tlog/merklelog"
)

// Reopening a log allocates memory linear in its file's size: 250 records of
// 4 KB are replayed in at most 64 bytes of allocation per byte of file. The
// count matters: copying the rest of the file at each line costs about N/2
// bytes a byte, which must clearly exceed 64.
func TestNew_ReplaysInMemoryLinearInTheLog(t *testing.T) {
	dir := t.TempDir()
	l, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 250 {
		if _, err := l.Append(context.Background(), []byte(fmt.Sprintf(`{"n":%d,"pad":"%04000d"}`, i, i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	var size int64
	if err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return err
	}); err != nil || size == 0 {
		t.Fatalf("log size %d: %v", size, err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	l2, err := merklelog.New(dir)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := int64(after.TotalAlloc - before.TotalAlloc); got > 64*size {
		t.Errorf("reopening a %d-byte log allocated %d bytes (%d a byte), want at most 64 a byte", size, got, got/size)
	}
}
