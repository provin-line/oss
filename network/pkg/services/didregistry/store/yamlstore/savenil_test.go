package yamlstore_test

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
)

// tree is every file and directory under root, and each file's bytes.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if e.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		b, err := os.ReadFile(p)
		out[rel] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// changed is the paths whose entry differs between before and after, sorted.
func changed(before, after map[string]string) []string {
	var out []string
	for p, b := range before {
		if a, ok := after[p]; !ok || a != b {
			out = append(out, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// The saves refuse a nil DID, a nil document, and a Pipeline's or a
// Process's nil delegation, with an error, and store nothing: the store's
// files are the same after the refusal as before it.
func TestSave_RefusesANilDIDDocumentOrDelegation(t *testing.T) {
	owner, pipe, proc := mustParse(t, ownerDID), mustParse(t, pipelineDID), mustParse(t, processDID)
	var (
		noDID *dplaax.DID
		noDoc *did.DIDDocument
		noDlg *delegation.DelegationCredential
	)
	for name, c := range map[string]struct {
		parents int // 0: none, 1: the owner, 2: the owner and the pipeline
		save    func(store.DIDStore) error
	}{
		"an owner with no DID":      {0, func(s store.DIDStore) error { return s.SaveOwner(noDID, doc(ownerDID, ownerDID)) }},
		"an owner with no document": {0, func(s store.DIDStore) error { return s.SaveOwner(owner, noDoc) }},
		"nothing for an owner":      {0, func(s store.DIDStore) error { return s.SaveOwner(noDID, noDoc) }},
		"a pipeline with no DID": {1, func(s store.DIDStore) error {
			return s.SavePipeline(noDID, doc(pipelineDID, ownerDID), sampleDelegation(pipelineDID))
		}},
		"a pipeline with no document":   {1, func(s store.DIDStore) error { return s.SavePipeline(pipe, noDoc, sampleDelegation(pipelineDID)) }},
		"a pipeline with no delegation": {1, func(s store.DIDStore) error { return s.SavePipeline(pipe, doc(pipelineDID, ownerDID), noDlg) }},
		"nothing for a pipeline":        {1, func(s store.DIDStore) error { return s.SavePipeline(noDID, noDoc, noDlg) }},
		"a process with no DID": {2, func(s store.DIDStore) error {
			return s.SaveProcess(noDID, doc(processDID, pipelineDID), sampleDelegation(processDID))
		}},
		"a process with no document":   {2, func(s store.DIDStore) error { return s.SaveProcess(proc, noDoc, sampleDelegation(processDID)) }},
		"a process with no delegation": {2, func(s store.DIDStore) error { return s.SaveProcess(proc, doc(processDID, pipelineDID), noDlg) }},
		"nothing for a process":        {2, func(s store.DIDStore) error { return s.SaveProcess(noDID, noDoc, noDlg) }},
	} {
		root := t.TempDir()
		s := yamlstore.New(root)
		if c.parents >= 1 {
			if err := s.SaveOwner(owner, doc(ownerDID, ownerDID)); err != nil {
				t.Fatal(err)
			}
		}
		if c.parents >= 2 {
			if err := s.SavePipeline(pipe, doc(pipelineDID, ownerDID), sampleDelegation(pipelineDID)); err != nil {
				t.Fatal(err)
			}
		}
		before := tree(t, root)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v, want an error", name, r)
				}
			}()
			if err := c.save(s); err == nil {
				t.Errorf("%s: saved, want an error", name)
			}
		}()
		if after := tree(t, root); !maps.Equal(before, after) {
			t.Errorf("%s: the store changed: %q", name, changed(before, after))
		}
	}
}

// Every method that takes a DID refuses a nil one with an error, and panics
// on none.
func TestEveryMethod_RefusesANilDID(t *testing.T) {
	s := newStore(t)
	var noDID *dplaax.DID
	for name, call := range map[string]func() error{
		"Resolve":              func() error { _, err := s.Resolve(noDID); return err },
		"ResolveDelegation":    func() error { _, err := s.ResolveDelegation(noDID); return err },
		"UpdateStatus":         func() error { return s.UpdateStatus(noDID, store.StatusRevoked) },
		"GetStatus":            func() error { _, err := s.GetStatus(noDID); return err },
		"AppendLifecycleEvent": func() error { return s.AppendLifecycleEvent(noDID, store.LifecycleEvent{}) },
		"ReadLifecycleLog":     func() error { _, err := s.ReadLifecycleLog(noDID); return err },
		"ListPipelines":        func() error { _, err := s.ListPipelines(noDID); return err },
		"ListProcesses":        func() error { _, err := s.ListProcesses(noDID); return err },
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s(nil): panicked: %v, want an error", name, r)
				}
			}()
			if err := call(); err == nil {
				t.Errorf("%s(nil): no error", name)
			}
		}()
	}
}
