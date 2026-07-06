package file_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/file"
	"github.com/provin-line/oss/vc"
)

// compile-time: *Writer must implement sink.Writer.
var _ sink.Writer = (*file.Writer)(nil)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", len(out)+1, err, sc.Text())
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Write appends one parseable NDJSON line per record, in the console line shape
// (credential / confidence / payload) — one encoder across surfaces.
func TestWrite_AppendsNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumed.ndjson")
	w, err := file.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := w.Write(ctx, sink.Record{Payload: []byte(`{"n":1}`)}); err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	v := vc.ConfidenceVerified
	if err := w.Write(ctx, sink.Record{
		Payload: []byte(`{"n":2}`),
		Verdict: &vc.VerifyResult{Overall: v},
	}); err != nil {
		t.Fatalf("Write 2: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if got := lines[0]["confidence"]; got != "unknown" {
		t.Errorf("line 1 confidence = %v, want unknown (nil verdict)", got)
	}
	if got := lines[1]["confidence"]; got != "verified" {
		t.Errorf("line 2 confidence = %v, want verified", got)
	}
	for i, k := range []string{"credential", "confidence", "payload"} {
		if _, ok := lines[0][k]; !ok {
			t.Errorf("line shape missing %q (field %d) — must match the console record shape", k, i)
		}
	}
}

// A reopened path appends — restart must not truncate previously delivered events.
func TestNew_ReopenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumed.ndjson")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		w, err := file.New(path)
		if err != nil {
			t.Fatalf("New #%d: %v", i+1, err)
		}
		if err := w.Write(ctx, sink.Record{Payload: []byte(`{}`)}); err != nil {
			t.Fatalf("Write #%d: %v", i+1, err)
		}
	}
	if lines := readLines(t, path); len(lines) != 2 {
		t.Fatalf("lines after reopen = %d, want 2 (append, not truncate)", len(lines))
	}
}

// An uncreatable path is a construction error (fail-closed at boot), and a
// cancelled ctx refuses the write.
func TestFailClosed(t *testing.T) {
	if _, err := file.New(filepath.Join(t.TempDir(), "no-such-dir", "x.ndjson")); err == nil {
		t.Error("New with a missing parent dir: want error")
	}

	path := filepath.Join(t.TempDir(), "consumed.ndjson")
	w, err := file.New(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Write(ctx, sink.Record{Payload: []byte(`{}`)}); err == nil {
		t.Error("Write with cancelled ctx: want error")
	}
	if lines := readLines(t, path); len(lines) != 0 {
		t.Errorf("cancelled write left %d lines, want 0", len(lines))
	}
}
