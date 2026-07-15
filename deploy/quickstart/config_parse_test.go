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
// The cause is a BUG IN THE PARSER, not in our configs. The HOCON spec says
// "anything between // or # and the next newline is considered a comment and
// ignored"; gurkankaymak/hocon v1.2.23 instead lets a `#` comment containing a
// `//` sequence SWALLOW THE FOLLOWING LINE. Two documents differing only in
// comment text — which the spec says is ignored — parse to different results.
// (A `//`-marked comment containing `//` is handled correctly; the `#` marker is
// what mis-tokenizes.) A URL in an explanatory comment is the natural way to
// write one, so ordinary prose triggers it.
//
// Parsing is therefore the weaker half of the guard. The failure only becomes
// LOUD when the swallowed line carries a brace; when it carries a key, the file
// parses and the setting silently disappears — which is exactly what had
// happened to three reference defaults (opa.base-url, cedar.base-url,
// registry.service-endpoints) with nobody the wiser. TestNoHashCommentContainsDoubleSlash
// is what catches the quiet case, before a later edit turns a harmless swallow
// into a lost default.
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

// This is a WORKAROUND for the parser bug described above, and it is stated as a
// house rule because that is the only thing we control: the shape is legal HOCON
// that our dependency mishandles. Nothing here may carry it — today's harmless
// swallow, where the eaten line happens to be another comment, becomes a
// silently dropped setting the moment someone inserts a key after it or reorders
// the block.
//
// Comments that must show a literal URL use the `//` marker instead, which the
// parser handles correctly. That is why this checks the MARKER, not the text.
// Retire this test if the dependency is fixed or replaced.
func TestNoHashCommentContainsDoubleSlash(t *testing.T) {
	root := repoRoot(t)
	var confs []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
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
	for _, p := range confs {
		rel, _ := filepath.Rel(root, p)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "//") {
				t.Errorf("%s:%d: a '#' comment containing '//' swallows the NEXT line — "+
					"use the '//' comment marker instead, or drop the scheme's slashes:\n  %s",
					rel, i+1, trimmed)
			}
		}
	}
}
