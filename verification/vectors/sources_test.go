package vectors_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readExpected reads a tab-separated table: lines starting with # and blank
// lines are skipped, and every other line must have exactly columns fields.
func readExpected(t *testing.T, path string, columns int) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var rows [][]string
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != columns {
			t.Fatalf("%s:%d: %d tab-separated fields, want %d", path, i+1, len(fields), columns)
		}
		rows = append(rows, fields)
	}
	return rows
}

// Every file under testdata/ is listed in SOURCES.tsv, once, with the SHA-256
// of its bytes: a vendored file that changes, or one added without a row,
// fails here.
func TestVendoredFilesMatchSources(t *testing.T) {
	rows := readExpected(t, "testdata/SOURCES.tsv", 4)
	listed := map[string]string{}
	for _, r := range rows {
		path, sum := r[0], r[1]
		if _, dup := listed[path]; dup {
			t.Errorf("SOURCES.tsv lists %s twice", path)
		}
		listed[path] = sum
		b, err := os.ReadFile(filepath.Join("testdata", path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		got := sha256.Sum256(b)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: SHA-256 %x, SOURCES.tsv says %s", path, got, sum)
		}
	}
	err := filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("testdata", p)
		if rel == "SOURCES.tsv" {
			return nil
		}
		if _, ok := listed[filepath.ToSlash(rel)]; !ok {
			t.Errorf("%s is under testdata/ but not in SOURCES.tsv", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
