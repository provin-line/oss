package filestore_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/vc"
)

// storecontract.Backend (contract_test.go) proves this backend keeps the same
// promises as its mem sibling. What is here is what only a FILESYSTEM can get
// wrong or prove: the on-disk layout an older binary has to keep reading, the
// create-only primitive, durability of directory creation, and restart.

func newBackend(t *testing.T) (*filestore.Backend, string) {
	t.Helper()
	dir := t.TempDir()
	b, err := filestore.NewBackend(dir)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	return b, dir
}

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

// TestVariantSubtreeIsInvisibleToTheOldLayout is the rollback plan, asserted.
//
// The pre-slice reader opened exactly "<bodyhex>.json" and skipped directories
// when listing. Both must stay true of what this backend writes, or rolling
// back to that binary would meet a layout it cannot read — the one moment
// nobody can ship a fix.
func TestVariantSubtreeIsInvisibleToTheOldLayout(t *testing.T) {
	b, dir := newBackend(t)
	body, variant := hex64('a'), hex64('b')
	wire := []byte(`{"body":"a"}`)
	if _, err := b.PutIfAbsent(body, variant, wire); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if err := b.WriteProjection(body, wire); err != nil {
		t.Fatalf("WriteProjection: %v", err)
	}

	// The old reader's Get: the flat file, by exact name.
	got, err := os.ReadFile(filepath.Join(dir, body+".json"))
	if err != nil {
		t.Fatalf("the old layout's file is not where it was: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("flat slot holds %s, want %s", got, wire)
	}

	// The old reader's ListHashes: files in the root, directories skipped,
	// foreign names ignored. It must see exactly the one body — the variant
	// subtree must not surface as an entry.
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var oldSees []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		if base, ok := strings.CutSuffix(de.Name(), ".json"); ok {
			oldSees = append(oldSees, base)
		}
	}
	if len(oldSees) != 1 || oldSees[0] != body {
		t.Errorf("the old reader would enumerate %v, want exactly [%s]", oldSees, body)
	}
}

// TestPutIfAbsentDoesNotReplace: the create-only primitive, at the level where
// it is actually decided. A rename-based write would pass every other test in
// this file and still destroy the held bytes the write-once check above needs
// to compare against.
func TestPutIfAbsentDoesNotReplace(t *testing.T) {
	b, dir := newBackend(t)
	body, variant := hex64('c'), hex64('d')
	first := []byte(`{"n":1}`)
	if existed, err := b.PutIfAbsent(body, variant, first); err != nil || existed {
		t.Fatalf("first PutIfAbsent: existed=%v err=%v", existed, err)
	}
	existed, err := b.PutIfAbsent(body, variant, []byte(`{"n":2}`))
	if err != nil {
		t.Fatalf("second PutIfAbsent: %v", err)
	}
	if !existed {
		t.Error("second PutIfAbsent reported the name as free")
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "variants", body, variant+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, first) {
		t.Errorf("the file was replaced: holds %s, want %s", onDisk, first)
	}
	// A failed create must not leave litter behind.
	assertNoTempFiles(t, filepath.Join(dir, "variants", body))
}

// TestPutIfAbsentIsCreateOnlyAcrossInstances reaches the case the in-process
// lock hides.
//
// storecontract's atomicity check races goroutines through ONE Backend, so its
// mutex serializes them and a replacing primitive would still look correct.
// Two instances over one root have no shared lock — the filesystem call itself
// is the whole arbitration, which is why it is os.Link (fails with EEXIST) and
// not os.Rename (replaces silently, destroying the bytes the write-once check
// above would have compared against).
//
// This is insurance against a misconfigured deployment sharing a root, NOT a
// claim of multi-process support: cross-process fencing is P1-D's, and nothing
// here makes the projection refresh or the read-modify-write sequences safe
// under two writers.
func TestPutIfAbsentIsCreateOnlyAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	const writers = 8
	body, variant := hex64('7'), hex64('8')

	var (
		mu       sync.Mutex
		created  int
		creator  []byte
		failures []error
		wg       sync.WaitGroup
	)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		b, err := filestore.NewBackend(dir) // a separate instance: no shared lock
		if err != nil {
			t.Fatalf("NewBackend: %v", err)
		}
		payload := []byte(fmt.Sprintf(`{"writer":%d}`, i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			existed, err := b.PutIfAbsent(body, variant, payload)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failures = append(failures, err)
			case !existed:
				created++
				creator = payload
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range failures {
		t.Errorf("PutIfAbsent: %v", err)
	}
	if created != 1 {
		t.Errorf("%d of %d writers on separate instances believed they created the entry, want exactly 1", created, writers)
	}
	held, err := os.ReadFile(filepath.Join(dir, "variants", body, variant+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if creator != nil && !bytes.Equal(held, creator) {
		t.Errorf("the entry holds %s but its creator wrote %s — a later writer replaced it", held, creator)
	}
	assertNoTempFiles(t, filepath.Join(dir, "variants", body))
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", de.Name())
		}
	}
}

// TestBackendSurvivesRestart: a fresh instance over the same directory sees
// everything the first one acknowledged. Evidence that does not survive a
// restart is not evidence (e2e finding #23).
func TestBackendSurvivesRestart(t *testing.T) {
	b, dir := newBackend(t)
	body, variant := hex64('e'), hex64('f')
	wire := []byte(`{"survives":true}`)
	if _, err := b.PutIfAbsent(body, variant, wire); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteProjection(body, wire); err != nil {
		t.Fatal(err)
	}

	restarted, err := filestore.NewBackend(dir)
	if err != nil {
		t.Fatalf("NewBackend (restart): %v", err)
	}
	got, err := restarted.ReadVariant(body, variant)
	if err != nil || !bytes.Equal(got, wire) {
		t.Errorf("after restart ReadVariant = %s (err %v), want %s", got, err, wire)
	}
	if proj, err := restarted.ReadProjection(body); err != nil || !bytes.Equal(proj, wire) {
		t.Errorf("after restart ReadProjection = %s (err %v), want %s", proj, err, wire)
	}
	bodies, err := restarted.ListBodyHexes("", 10)
	if err != nil || len(bodies) != 1 || bodies[0] != body {
		t.Errorf("after restart ListBodyHexes = %v (err %v), want [%s]", bodies, err, body)
	}
}

// TestListBodyHexesSeesAVariantOnlyBody is the crash window between the two
// writes: the variant is durable, the projection never landed. The body is
// held, so the enumeration the forward index is built from must say so.
func TestListBodyHexesSeesAVariantOnlyBody(t *testing.T) {
	b, _ := newBackend(t)
	body := hex64('1')
	if _, err := b.PutIfAbsent(body, hex64('2'), []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := b.ListBodyHexes("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != body {
		t.Errorf("ListBodyHexes = %v, want [%s] — a body whose projection never landed is still held", got, body)
	}
}

// TestListBodyHexesIgnoresAnEmptyVariantDir: the other side of that window —
// mkdir succeeded, the link never happened. Nothing is held, so nothing is
// enumerated.
func TestListBodyHexesIgnoresAnEmptyVariantDir(t *testing.T) {
	b, dir := newBackend(t)
	if err := os.Mkdir(filepath.Join(dir, "variants", hex64('3')), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := b.ListBodyHexes("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("ListBodyHexes = %v, want empty — an empty directory holds no evidence", got)
	}
}

// TestAVanishedRootIsNotAnAbsentCredential: a deleted or unmounted store must
// not answer "never held it". That is a storage failure being reported as a
// fact about provenance.
func TestAVanishedRootIsNotAnAbsentCredential(t *testing.T) {
	b, dir := newBackend(t)
	body, variant := hex64('4'), hex64('5')
	if _, err := b.PutIfAbsent(body, variant, []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	_, err := b.ReadVariant(body, variant)
	if err == nil {
		t.Fatal("ReadVariant on a vanished store succeeded")
	}
	if errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("a vanished store read as an absent credential: %v", err)
	}
	if _, err := b.ReadProjection(body); errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("a vanished store read as an absent projection: %v", err)
	}
}

// TestBackendRejectsNamesThatAreNotHex: paths are built only from names this
// check has passed, so no separator or dot segment can reach the filesystem
// even if a layer above went wrong.
func TestBackendRejectsNamesThatAreNotHex(t *testing.T) {
	b, _ := newBackend(t)
	bad := []string{"", "..", "../escape", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.ToUpper(hex64('a')), strings.Repeat("g", 64)}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := b.PutIfAbsent(name, hex64('a'), []byte(`{}`)); !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("PutIfAbsent(body=%q) = %v, want ErrInvalidArgument", name, err)
			}
			if _, err := b.PutIfAbsent(hex64('a'), name, []byte(`{}`)); !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("PutIfAbsent(variant=%q) = %v, want ErrInvalidArgument", name, err)
			}
			if _, err := b.ReadVariant(hex64('a'), name); !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("ReadVariant(variant=%q) = %v, want ErrInvalidArgument", name, err)
			}
			if _, err := b.ReadProjection(name); !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("ReadProjection(%q) = %v, want ErrInvalidArgument", name, err)
			}
		})
	}
}

// TestBootFailsClosedOnAnUnwritableRoot: a node that cannot persist evidence
// must not start and discover it at the first write.
func TestBootFailsClosedOnAnUnwritableRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := filestore.NewBackend(dir); err == nil {
		t.Error("NewBackend succeeded on a read-only root")
	}
}

// --- the façade over this backend ---
//
// The façade's semantics are proven once, against every backend, in
// vcresolver's own tests. What is worth proving HERE is the part that only
// exists on disk: that the layout the façade produces is the one an older
// binary reads, and that the self-healing survives a real restart.

func facadeCred(t *testing.T, proofValue string) *vc.PipelinePassCredential {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "s1"},
		"proof": map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod", "created": "2026-07-01T00:00:01Z",
			"proofValue": proofValue,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return &c
}

// TestFacadeLeavesTheOldReaderAWorkingStore: after the façade admits two
// variants, the flat file an older binary opens holds the winner — the same
// document this binary serves. Rolling back must not change what a body
// resolves to.
func TestFacadeLeavesTheOldReaderAWorkingStore(t *testing.T) {
	b, dir := newBackend(t)
	store := vcresolver.NewVariantStore(b)
	body, variantA := mustPutVariant(t, store, facadeCred(t, "zA"))
	_, variantB := mustPutVariant(t, store, facadeCred(t, "zB"))

	winner := variantA
	if variantB < winner {
		winner = variantB
	}
	served, err := store.Get(body)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	servedID, err := served.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	if servedID != winner {
		t.Errorf("Get served %s, want the set minimum %s", servedID, winner)
	}

	// What the old binary reads, by exact file name.
	flat, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(body, "sha256:")+".json"))
	if err != nil {
		t.Fatalf("the old reader's file is missing: %v", err)
	}
	exact, err := store.GetVariant(body, winner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(flat, exact) {
		t.Errorf("the old reader would see a different document than this one serves:\n old: %s\nthis: %s", flat, exact)
	}
}

// TestFacadeHealsAStaleProjectionAcrossRestart is the crash window, on real
// files: the variant landed, the projection refresh never did, and the process
// died. A reader must not keep serving the stale pointer until that body is
// next written.
func TestFacadeHealsAStaleProjectionAcrossRestart(t *testing.T) {
	b, dir := newBackend(t)
	store := vcresolver.NewVariantStore(b)
	first := facadeCred(t, "zA")
	body, variantA := mustPutVariant(t, store, first)
	bodyHex := strings.TrimPrefix(body, "sha256:")

	// Land a second variant WITHOUT refreshing the projection — the state a
	// crash between the two writes leaves behind.
	second := facadeCred(t, "zB")
	wireB, err := second.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	variantB, err := second.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	variantBHex, _ := vc.WireVariantHex(variantB)
	if _, err := b.PutIfAbsent(bodyHex, variantBHex, wireB); err != nil {
		t.Fatal(err)
	}

	winner, stale := variantA, variantB
	if variantB < variantA {
		winner, stale = variantB, variantA
	}
	if winner == stale {
		t.Fatal("fixture bug: the two variants collided")
	}

	// The restart: a fresh instance and a fresh façade over the same files.
	restarted, err := filestore.NewBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	reader := vcresolver.NewVariantStore(restarted)
	got, err := reader.Get(body)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	gotID, err := got.WireVariantID()
	if err != nil {
		t.Fatal(err)
	}
	if gotID != winner {
		t.Errorf("after restart Get served %s, want the set minimum %s", gotID, winner)
	}

	// ...and the read repaired the flat slot, so the older binary agrees too.
	flat, err := os.ReadFile(filepath.Join(dir, bodyHex+".json"))
	if err != nil {
		t.Fatal(err)
	}
	exact, err := reader.GetVariant(body, winner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(flat, exact) {
		t.Error("the read served the winner but left the old reader looking at a stale document")
	}
}

func mustPutVariant(t *testing.T, s *vcresolver.VariantStore, cred *vc.PipelinePassCredential) (string, string) {
	t.Helper()
	body, variant, err := s.PutVariant(cred)
	if err != nil {
		t.Fatalf("PutVariant: %v", err)
	}
	return body, variant
}

// TestTamperedFilesAreRejectedByTheFacade ports what the old flat store's own
// Get enforced, to where that check lives now: the façade validates, this
// backend just reads. The tampering is done to REAL files, which is the point —
// the memstore-backed tests reach these branches through a fake, and only this
// one proves the same verdicts hold over the filesystem the node actually runs
// on.
//
// Damage must never read as absence. "We never held it" and "what we hold is
// not what it claims to be" are different facts about provenance, and only one
// of them means someone interfered.
func TestTamperedFilesAreRejectedByTheFacade(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, dir, bodyHex, variantHex string, other []byte)
	}{
		{
			name: "a different document under the variant's name",
			corrupt: func(t *testing.T, dir, bodyHex, variantHex string, other []byte) {
				write(t, filepath.Join(dir, "variants", bodyHex, variantHex+".json"), other)
			},
		},
		{
			name: "unparseable bytes under the variant's name",
			corrupt: func(t *testing.T, dir, bodyHex, variantHex string, _ []byte) {
				write(t, filepath.Join(dir, "variants", bodyHex, variantHex+".json"), []byte("not json"))
			},
		},
		{
			name: "the same document, re-spelled",
			corrupt: func(t *testing.T, dir, bodyHex, variantHex string, _ []byte) {
				p := filepath.Join(dir, "variants", bodyHex, variantHex+".json")
				held, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				write(t, p, []byte(strings.Replace(string(held), "{", "{ ", 1)))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, dir := newBackend(t)
			store := vcresolver.NewVariantStore(b)
			body, variant := mustPutVariant(t, store, facadeCred(t, "zA"))
			bodyHex := strings.TrimPrefix(body, "sha256:")
			variantHex, _ := vc.WireVariantHex(variant)
			other, err := facadeCred(t, "zB").MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}

			tc.corrupt(t, dir, bodyHex, variantHex, other)

			reader := vcresolver.NewVariantStore(mustBackend(t, dir))
			_, err = reader.GetVariant(body, variant)
			if err == nil {
				t.Fatal("GetVariant served a tampered file")
			}
			if errors.Is(err, vcresolver.ErrNotFound) {
				t.Errorf("a tampered file read as an absent variant: %v", err)
			}
		})
	}
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustBackend(t *testing.T, dir string) *filestore.Backend {
	t.Helper()
	b, err := filestore.NewBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAVanishedVariantSubtreeIsNotAnAbsentVariant is Codex's third finding.
//
// The root can survive while the variant subtree is removed or unmounted. The
// root check passes, the variant file is ENOENT, and every variant this store
// holds would answer "never held" — a storage failure reported as a fact about
// provenance, which is the same laundering the vanished-root check exists to
// prevent, one directory down.
func TestAVanishedVariantSubtreeIsNotAnAbsentVariant(t *testing.T) {
	b, dir := newBackend(t)
	body, variant := hex64('9'), hex64('a')
	if _, err := b.PutIfAbsent(body, variant, []byte(`{"held":true}`)); err != nil {
		t.Fatal(err)
	}
	// The subtree goes; the root stays.
	if err := os.RemoveAll(filepath.Join(dir, "variants")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("precondition: the root must still be there: %v", err)
	}

	_, err := b.ReadVariant(body, variant)
	if err == nil {
		t.Fatal("ReadVariant succeeded with the subtree gone")
	}
	if errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("a vanished variant subtree read as an absent variant: %v", err)
	}
	if _, err := b.ListVariantHexes(body, "", 10); err == nil {
		t.Error("ListVariantHexes answered 'no variants' with the subtree gone")
	}
}

// TestAnAbsentBodyDirectoryIsStillARealMiss: the check above must not turn
// every ordinary miss into an error — a body that simply has no variants has
// no directory, and that is a normal answer.
func TestAnAbsentBodyDirectoryIsStillARealMiss(t *testing.T) {
	b, _ := newBackend(t)
	if _, err := b.ReadVariant(hex64('b'), hex64('c')); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("ReadVariant on a body with no variants = %v, want ErrNotFound", err)
	}
	page, err := b.ListVariantHexes(hex64('b'), "", 10)
	if err != nil || len(page) != 0 {
		t.Errorf("ListVariantHexes on a body with no variants = %v (err %v), want an empty page", page, err)
	}
}

// TestBootSweepsOrphanedTempsInBodyDirectories: a kill between os.CreateTemp
// and its deferred cleanup leaves a temp file one level deeper than openDir
// ever looked — in variants/<bodyHex>/ — so no restart removed it. Harmless to
// every read (the .json + hex64 filter excludes it) and an unbounded disk leak,
// which is why it stayed invisible.
func TestBootSweepsOrphanedTempsInBodyDirectories(t *testing.T) {
	b, dir := newBackend(t)
	body := hex64('d')
	if _, err := b.PutIfAbsent(body, hex64('e'), []byte(`{"held":true}`)); err != nil {
		t.Fatal(err)
	}
	bodyDir := filepath.Join(dir, "variants", body)
	orphan := filepath.Join(bodyDir, ".tmp-crashed")
	write(t, orphan, []byte("half a variant"))
	// Also one directly in the subtree, which openDir did already handle — the
	// sweep must not regress it.
	write(t, filepath.Join(dir, "variants", ".tmp-old"), []byte("x"))

	if _, err := filestore.NewBackend(dir); err != nil { // the restart
		t.Fatalf("NewBackend: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("the orphaned temp in %s survived a restart (err %v)", bodyDir, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "variants", ".tmp-old")); !os.IsNotExist(err) {
		t.Error("the subtree's own temp survived a restart")
	}
	// The sweep must take temps and nothing else.
	if _, err := os.Stat(filepath.Join(bodyDir, hex64('e')+".json")); err != nil {
		t.Errorf("the sweep removed a held variant: %v", err)
	}
}
