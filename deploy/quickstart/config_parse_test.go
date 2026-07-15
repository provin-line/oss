package quickstart_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gurkankaymak/hocon"
)

// Every .conf this repository ships must actually parse. The quickstart's
// application.conf did not — for its entire history — and nothing noticed:
// `docker compose config` validates the compose file, not the node config the
// container reads, and the node crash-looped behind a healthcheck that reported
// Healthy. The P0-6 closure condition that demanded an ACTUAL boot is what
// surfaced it.
//
// The trigger is a `//` sequence inside a `#` comment (a URL in an explanatory
// comment is the natural way to write one): the parser's structural view then
// diverges from the document's, and it rejects the file's final brace as a
// stray. Rather than encode that rule — the exact condition is not fully
// characterized, and a rule stated too narrowly would miss the next variant —
// this test asserts the property that actually matters: the loader parses it.
func TestShippedConfigsParse(t *testing.T) {
	root := repoRoot(t)
	var confs []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Vendored and generated trees are not ours to police.
			if name := info.Name(); name == ".git" || name == "node_modules" || name == "gen" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".conf") {
			confs = append(confs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(confs) == 0 {
		t.Fatal("found no .conf files — the walk is broken, not the configs")
	}
	for _, p := range confs {
		rel, _ := filepath.Rel(root, p)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: parser panicked: %v", rel, r)
				}
			}()
			if _, err := hocon.ParseString(string(b)); err != nil {
				t.Errorf("%s does not parse: %v", rel, err)
			}
		}()
	}
	t.Logf("parsed %d shipped .conf files", len(confs))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the test directory")
	return ""
}
