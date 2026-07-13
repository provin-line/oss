//go:build regen

// This file is a source-of-truth mutation tool, not part of the conformance
// assertion suite. It is compiled ONLY under `-tags regen` so a routine
// `go test ./...` can never rewrite the vector corpus, even with the
// DPLAAX_REGEN env var leaked — the env gate below is then a second,
// independent guard on top of this compile-time isolation.

package conformance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/vc"
)

// specVectorsDir is the source-of-truth vector directory (dplaax.spec_draft
// vectors/), the canonical set that scripts/sync-spec-vectors.sh vendors into
// conformance/vectors/dplaax. Overridable via DPLAAX_SPEC_VECTORS_DIR for
// non-sibling checkouts; the default matches the sibling layout the sync
// script already assumes.
func specVectorsDir() string {
	if d := os.Getenv("DPLAAX_SPEC_VECTORS_DIR"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "dplaax.spec_draft", "vectors")
}

// TestRegenerateDplaaxDerivedHashes is a golden-update tool, not a conformance
// assertion: it is skipped unless DPLAAX_REGEN=1. It recomputes every
// @context-dependent derived hash in the SoT vectors — source roots
// (vc.NewSourceCommitment) and content addresses (PipelinePassCredential.Hash)
// — and rewrites the SoT JSON in place. Each value is computed through the
// exact vc code path the corresponding assertion uses, so a regenerated value
// is by construction the value TestDplaaxAllVectors will then check; that
// path-identity is the whole reason this lives in the harness rather than a
// standalone tool. Run after a @context or canonicalization change, then
// scripts/sync-spec-vectors.sh to re-vendor and regenerate MANIFEST.sha256.
//
// Always invoke with -tags regen and -count=1. The build tag compiles this
// tool in at all; -count=1 defeats go's test cache, which does not track the
// os.ReadFile inputs, so a second plain run would otherwise return the first
// run's cached log without re-executing (the operation is idempotent, so that
// is only confusing, not corrupting).
//
//	DPLAAX_REGEN=1 go test -tags regen ./conformance/ -run TestRegenerateDplaaxDerivedHashes -count=1
//
// The allow-list is explicit on purpose. Negative vectors pin deliberately
// wrong values (commitment-008's all-zero root, resolver-002's 0xff… key) and
// short-circuit fixtures (commitment-009/010) whose root is never recomputed;
// regenerating those would flip a verdict or churn a decorative value, so they
// are excluded. commitment-011 short-circuits too but shares its source set
// with 005/013, so it is regenerated to keep the corpus internally honest.
func TestRegenerateDplaaxDerivedHashes(t *testing.T) {
	if os.Getenv("DPLAAX_REGEN") != "1" {
		t.Skip("golden-update tool: set DPLAAX_REGEN=1 to rewrite derived-hash expects in the SoT vectors")
	}
	dir := specVectorsDir()

	// source_root over input.sources, written to expect.source_root
	// (construction family).
	for _, id := range []string{"commitment-005", "commitment-006", "commitment-007"} {
		regenSourceRootExpect(t, dir, id)
	}
	// source_root over input.sources, written to the credential's claimed
	// input.credential.credentialSubject.source_root (verification family;
	// 013 is the verified-positive path, 011 tracks 005's set).
	for _, id := range []string{"commitment-011", "commitment-013"} {
		regenSourceRootClaimed(t, dir, id)
	}
	// content addresses (Hash over the served body).
	regenContentAddress(t, dir, "resolver-001")
	regenResolverImmutability(t, dir, "resolver-003")
	regenResolverBodyEncoding(t, dir, "resolver-008")
	// previousCredential = Hash(in-file predecessor).
	for _, id := range []string{"chain-006", "chain-007", "chain-008"} {
		regenChainPrev(t, dir, id)
	}
}

// regenSourceRootExpect recomputes the construction-family source_root over
// input.sources and rewrites expect.source_root.
func regenSourceRootExpect(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Sources             []json.RawMessage `json:"sources"`
			SourceRootCanonical string            `json:"source_root_canonical"`
		} `json:"input"`
		Expect struct {
			SourceRoot string `json:"source_root"`
		} `json:"expect"`
	}
	mustParse(t, raw, &vec)
	newRoot := computeSourceRoot(t, id, vec.Input.Sources, vec.Input.SourceRootCanonical)
	replaceInFile(t, path, raw, vec.Expect.SourceRoot, newRoot)
}

// regenSourceRootClaimed recomputes the verification-family source_root over
// input.sources and rewrites the credential's own claimed
// input.credential.credentialSubject.source_root. The canonicalization id is
// read from the claim (VerifySourceCommitment recomputes under the claimed
// canonical), matching the assertion path exactly.
func regenSourceRootClaimed(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Sources    []json.RawMessage `json:"sources"`
			Credential struct {
				CredentialSubject struct {
					SourceRoot          string `json:"source_root"`
					SourceRootCanonical string `json:"source_root_canonical"`
				} `json:"credentialSubject"`
			} `json:"credential"`
		} `json:"input"`
	}
	mustParse(t, raw, &vec)
	claim := vec.Input.Credential.CredentialSubject
	newRoot := computeSourceRoot(t, id, vec.Input.Sources, claim.SourceRootCanonical)
	replaceInFile(t, path, raw, claim.SourceRoot, newRoot)
}

func computeSourceRoot(t *testing.T, id string, rawSources []json.RawMessage, canonical string) string {
	t.Helper()
	sources := make([]*vc.PipelinePassCredential, len(rawSources))
	for i, r := range rawSources {
		sources[i] = mustCred(t, r)
	}
	sc, err := vc.NewSourceCommitment(sources, canonical)
	if err != nil {
		t.Fatalf("%s: NewSourceCommitment: %v", id, err)
	}
	return sc.SourceRoot
}

// regenContentAddress recomputes input.key = Hash(input.body) (resolver-001).
func regenContentAddress(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Key  string `json:"key"`
			Body string `json:"body"`
		} `json:"input"`
	}
	mustParse(t, raw, &vec)
	newKey := mustHash(t, id, []byte(vec.Input.Body))
	replaceInFile(t, path, raw, vec.Input.Key, newKey)
}

// regenResolverImmutability rewrites the shared queried key to the content
// address of the first lookup's returned body (resolver-003). The second
// lookup returns a different body that still fails to address to the key —
// the immutability violation the vector rejects — so the reject verdict holds.
func regenResolverImmutability(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Sequence []struct {
				Op           string `json:"op"`
				Key          string `json:"key"`
				ReturnedBody string `json:"returned_body"`
			} `json:"sequence"`
		} `json:"input"`
	}
	mustParse(t, raw, &vec)
	if len(vec.Input.Sequence) == 0 {
		t.Fatalf("%s: empty sequence", id)
	}
	first := vec.Input.Sequence[0]
	newKey := mustHash(t, id, []byte(first.ReturnedBody))
	// Both lookups query the same key; replaceInFile updates every occurrence.
	replaceInFile(t, path, raw, first.Key, newKey)
}

// regenResolverBodyEncoding re-encodes the base64url served body with the
// frozen URIs and recomputes entry.hash (resolver-008). The URIs live inside
// the base64 blob, so the plain-text find-replace cannot reach them — this is
// the only vector whose body freeze happens here.
func regenResolverBodyEncoding(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Entry struct {
				Hash string `json:"hash"`
				Body string `json:"body"`
			} `json:"entry"`
		} `json:"input"`
	}
	mustParse(t, raw, &vec)
	decoded, err := base64.RawURLEncoding.DecodeString(vec.Input.Entry.Body)
	if err != nil {
		t.Fatalf("%s: base64url decode: %v", id, err)
	}
	frozen := freezeContextURIs(decoded)
	newBody := base64.RawURLEncoding.EncodeToString(frozen)
	newHash := mustHash(t, id, frozen)
	// Both replacements go through the same not-found guard as replaceInFile,
	// so a body or hash that is no longer stored verbatim fails loudly rather
	// than silently rewriting one and leaving the vector internally inconsistent.
	out, _ := replaceExactly(t, id+" body", raw, vec.Input.Entry.Body, newBody)
	out, _ = replaceExactly(t, id+" hash", out, vec.Input.Entry.Hash, newHash)
	mustWriteVector(t, path, out)
	t.Logf("%s: re-encoded base64 body + hash -> %s", id, newHash)
}

// regenChainPrev rewrites chain[1]'s previousCredential to the content address
// of the in-file predecessor chain[0] (chain-006/007/008). The link is valid
// in all three; 007/008 reject on data-flow continuity, not the link, so the
// verdicts are unchanged.
func regenChainPrev(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	raw := mustReadVector(t, path, id)
	var vec struct {
		Input struct {
			Chain []json.RawMessage `json:"chain"`
		} `json:"input"`
	}
	mustParse(t, raw, &vec)
	if len(vec.Input.Chain) < 2 {
		t.Fatalf("%s: chain shorter than 2", id)
	}
	pred := mustCred(t, vec.Input.Chain[0])
	newHash := mustHashCred(t, id, pred)
	var succ struct {
		CredentialSubject struct {
			PreviousCredential string `json:"previousCredential"`
		} `json:"credentialSubject"`
	}
	if err := json.Unmarshal(vec.Input.Chain[1], &succ); err != nil {
		t.Fatalf("%s: parse chain[1]: %v", id, err)
	}
	replaceInFile(t, path, raw, succ.CredentialSubject.PreviousCredential, newHash)
}

func freezeContextURIs(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("poc.dplaax.dev/vc/v1"), []byte("dplaax.dev/vc/v1"))
	b = bytes.ReplaceAll(b, []byte("poc.provin.dev/vc/v1"), []byte("provin.dev/vc/v1"))
	return b
}

func mustHash(t *testing.T, id string, body []byte) string {
	t.Helper()
	return mustHashCred(t, id, mustCred(t, json.RawMessage(body)))
}

func mustHashCred(t *testing.T, id string, cred *vc.PipelinePassCredential) string {
	t.Helper()
	h, err := cred.Hash()
	if err != nil {
		t.Fatalf("%s: Hash: %v", id, err)
	}
	return h
}

func mustReadVector(t *testing.T, path, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: read: %v", id, err)
	}
	return raw
}

func mustWriteVector(t *testing.T, path string, out []byte) {
	t.Helper()
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("%s: write: %v", path, err)
	}
}

// replaceInFile replaces every occurrence of old with new in raw and writes
// the result to path. It fails if old is empty or absent, so a silently
// missed field can never leave a stale value behind. Derived hashes are unique
// 64-hex strings, so replacing all occurrences within a single file is the
// intended behavior (e.g. a shared queried key that appears twice).
// replaceExactly replaces every occurrence of oldVal with newVal in raw and
// returns the rewritten bytes and the occurrence count. It fails if oldVal is
// empty or absent, so a silently missed field can never leave a stale value
// behind. Derived hashes are unique 64-hex strings, so replacing all
// occurrences within a single file is the intended behavior (e.g. a shared
// queried key that appears twice).
func replaceExactly(t *testing.T, label string, raw []byte, oldVal, newVal string) ([]byte, int) {
	t.Helper()
	if oldVal == "" {
		t.Fatalf("%s: empty value to replace", label)
	}
	n := bytes.Count(raw, []byte(oldVal))
	if n == 0 {
		t.Fatalf("%s: value %q not found", label, oldVal)
	}
	return bytes.ReplaceAll(raw, []byte(oldVal), []byte(newVal)), n
}

func replaceInFile(t *testing.T, path string, raw []byte, oldVal, newVal string) {
	t.Helper()
	out, n := replaceExactly(t, filepath.Base(path), raw, oldVal, newVal)
	mustWriteVector(t, path, out)
	t.Logf("%s: %s -> %s (%d occurrence(s))", filepath.Base(path), oldVal, newVal, n)
}
