package quickstart_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hocon "github.com/o3co/go.hocon"
)

// Every .conf this repository ships must actually parse.
//
// This exists because one of them did not — for its whole history, on every
// machine. `docker compose config` validates the compose file, not the node
// config inside the container, so nothing looked at it until the P0-6 closure
// condition demanded an actual boot and the node turned out to be crash-looping
// behind a healthcheck that reported Healthy.
//
// The parse failure was a defect in the HOCON library then in use
// (gurkankaymak/hocon), since replaced by o3co/go.hocon — see the hoconconfig
// package doc. The library changed; the reason to check did not. A config file
// is read once per boot, by a dependency, and its failures are as likely to be
// silent as loud: this asserts the thing that matters, that the parser we
// actually ship with accepts what we actually ship.
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
