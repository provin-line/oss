package bundle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/bundle"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

const (
	registryID = "poc.dplaax.dev"
	ownerDID   = "did:dplaax:poc.dplaax.dev:org:acme"
	originDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:procA"
	childDID   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:procB"
)

// --- fixture plumbing -------------------------------------------------------

type memKeyStore struct{ keys map[string][]byte }

func newMemKeyStore() *memKeyStore { return &memKeyStore{keys: map[string][]byte{}} }

func (m *memKeyStore) SaveKeyPair(didStr string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[didStr+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}

func (m *memKeyStore) GetPrivateKey(didStr string, keyID keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[didStr+"#"+string(keyID)]
	if !ok {
		return nil, fmt.Errorf("key not found: %w", keystore.ErrNotFound)
	}
	return k, nil
}

func (m *memKeyStore) Sign(didStr string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(didStr, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}

func (m *memKeyStore) DeleteKeys(string) error { return nil }

// didDoc builds a DID Document; a non-nil pub attaches an AssertionMethod key.
func didDoc(t *testing.T, id, controller string, pub []byte) []byte {
	t.Helper()
	fields := did.DocumentFields{
		Context: did.IssuedDocumentContexts(),
		ID:      id, Controller: controller,
	}
	if pub != nil {
		vmID := id + "#signing"
		vm, err := did.NewMultikeyVerificationMethod(vmID, id, pub)
		if err != nil {
			panic(err) // a non-Ed25519 fixture key is a test bug
		}
		fields.VerificationMethod = []did.VerificationMethod{vm}
		fields.AssertionMethod = []string{vmID}
	}
	raw, err := did.New(fields).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal did doc %s: %v", id, err)
	}
	return raw
}

type mapCredSource map[string][]byte

func (m mapCredSource) FetchCredential(_ context.Context, hash string) ([]byte, error) {
	b, ok := m[hash]
	if !ok {
		return nil, fmt.Errorf("no credential %s", hash)
	}
	return b, nil
}

type mapDocSource map[string][]byte

func (m mapDocSource) FetchDocument(_ context.Context, didStr string) ([]byte, error) {
	b, ok := m[didStr]
	if !ok {
		return nil, fmt.Errorf("no document %s", didStr)
	}
	return b, nil
}

// fixture is a genuine signed two-hop chain (origin -> head) with the three
// authority documents (two processes + shared self-controlled owner).
type fixture struct {
	head, origin string // content addresses
	creds        mapCredSource
	docs         mapDocSource
}

func buildFixture(t *testing.T, originIssuer, childIssuer string) fixture {
	t.Helper()
	gen := ed25519.Generator{}
	kpA, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate A: %v", err)
	}
	kpB, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate B: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(originIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpA}); err != nil {
		t.Fatalf("SaveKeyPair A: %v", err)
	}
	if err := ks.SaveKeyPair(childIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpB}); err != nil {
		t.Fatalf("SaveKeyPair B: %v", err)
	}
	b := vc.NewBuilder(ks)

	const (
		hashIn  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		hashMid = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		hashOut = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	)
	origin, err := b.BuildFirstDrop(originIssuer, string(keystore.KeyIDSigning), originIssuer+"#signing",
		vc.CredentialSubjectFields{
			PipelineID: "p1", ProcessID: "procA",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           hashIn, OutputHash: hashMid,
		}, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	child, err := b.BuildChainPreserving(childIssuer, string(keystore.KeyIDSigning), childIssuer+"#signing",
		vc.CredentialSubjectFields{
			PipelineID: "p1", ProcessID: "procB",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           hashMid, OutputHash: hashOut,
		}, origin, nil)
	if err != nil {
		t.Fatalf("BuildChainPreserving: %v", err)
	}

	f := fixture{creds: mapCredSource{}, docs: mapDocSource{}}
	for _, c := range []*vc.PipelinePassCredential{origin, child} {
		h, err := c.Hash()
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		raw, err := c.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		f.creds[h] = raw
	}
	f.origin, _ = origin.Hash()
	f.head, _ = child.Hash()

	f.docs[originIssuer] = didDoc(t, originIssuer, ownerDID, kpA.PublicKey)
	f.docs[childIssuer] = didDoc(t, childIssuer, ownerDID, kpB.PublicKey)
	f.docs[ownerDID] = didDoc(t, ownerDID, ownerDID, nil)
	return f
}

func exportFixture(t *testing.T, f fixture) (dir string, res *bundle.ExportResult) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "b")
	res, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return dir, res
}

func hexOf(hash string) string { return strings.TrimPrefix(hash, "sha256:") }

func sha256Of(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rewriteManifest loads, mutates, and rewrites the manifest — the
// consistent-attacker helper (no digest anchor survives this by design).
func rewriteManifest(t *testing.T, dir string, mutate func(m *bundle.Manifest)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m bundle.Manifest
	// decoder-hygiene-exempt: test-side manifest surgery on a fixture the test itself wrote.
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	mutate(&m)
	// canonicalizer-hygiene-exempt: test fixture rewrite; digest anchors are deliberately broken here.
	out, err := json.Marshal(&m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// --- export -----------------------------------------------------------------

func TestExport_LayoutAndManifest(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, res := exportFixture(t, f)

	wantFiles := []string{
		"credentials/" + hexOf(f.origin) + ".json",
		"credentials/" + hexOf(f.head) + ".json",
		"diddocs/" + registryID + "/did/org/acme/pipeline/p1/process/procA/did.json",
		"diddocs/" + registryID + "/did/org/acme/pipeline/p1/process/procB/did.json",
		"diddocs/" + registryID + "/did/org/acme/did.json",
	}
	for _, rel := range wantFiles {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("expected bundle file %s: %v", rel, err)
		}
		got, ok := res.Manifest.Files[rel]
		if !ok {
			t.Errorf("manifest.files missing %s", rel)
			continue
		}
		if want := sha256Of(t, filepath.Join(dir, rel)); got != want {
			t.Errorf("manifest.files[%s] = %s, want %s", rel, got, want)
		}
	}
	if len(res.Manifest.Files) != len(wantFiles) {
		t.Errorf("manifest.files has %d entries, want %d", len(res.Manifest.Files), len(wantFiles))
	}

	m := res.Manifest
	if m.V != 1 || m.Scope != bundle.ScopeLinear {
		t.Errorf("manifest v=%d scope=%q, want 1/%q", m.V, m.Scope, bundle.ScopeLinear)
	}
	if m.Head != f.head {
		t.Errorf("manifest head = %s, want %s", m.Head, f.head)
	}
	if len(m.Chain) != 2 || m.Chain[0] != f.origin || m.Chain[1] != f.head {
		t.Errorf("manifest chain = %v, want [origin head]", m.Chain)
	}
	if len(m.DIDDocuments) != 3 {
		t.Errorf("manifest didDocuments = %v, want 3 entries", m.DIDDocuments)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		t.Errorf("manifest createdAt %q: %v", m.CreatedAt, err)
	}

	// Credential bytes are archived verbatim.
	got, err := os.ReadFile(filepath.Join(dir, "credentials/"+hexOf(f.head)+".json"))
	if err != nil || string(got) != string(f.creds[f.head]) {
		t.Errorf("archived head bytes differ from source (err %v)", err)
	}

	// The bundle digest is the manifest bytes' content address.
	if want := sha256Of(t, filepath.Join(dir, "manifest.json")); res.Digest != want {
		t.Errorf("bundle digest = %s, want %s", res.Digest, want)
	}
}

func TestExport_LyingCredentialSource_Rejected(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	f.creds[f.head] = f.creds[f.origin] // wrong bytes for the requested address
	_, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), f.head, f.creds, f.docs, bundle.ExportOptions{})
	if err == nil || !strings.Contains(err.Error(), f.head) {
		t.Fatalf("export with lying source: err=%v, want content-address mismatch naming %s", err, f.head)
	}
}

func TestExport_UnverifiableChain_Aborts(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	delete(f.docs, ownerDID) // authority chain cannot terminate
	_, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), f.head, f.creds, f.docs, bundle.ExportOptions{})
	if err == nil {
		t.Fatal("export of a chain that does not verify: want error")
	}
}

func TestExport_ExistingDir_Rejected(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir := t.TempDir() // exists
	if _, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{}); err == nil {
		t.Fatal("export into an existing directory: want error")
	}
}

func TestExport_MaxDepth_Bounds(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	_, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), f.head, f.creds, f.docs,
		bundle.ExportOptions{MaxDepth: 1})
	if err == nil {
		t.Fatal("2-hop chain with MaxDepth=1: want error")
	}
}

func TestExport_InvalidHead_Rejected(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	if _, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), "not-a-hash", f.creds, f.docs, bundle.ExportOptions{}); err == nil {
		t.Fatal("invalid head: want error")
	}
}

func TestExport_CaseFoldCollision_Rejected(t *testing.T) {
	// Two distinct issuers whose DIDs differ only by case: on a
	// case-insensitive filesystem their diddocs paths collide.
	const cased = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:PROCA"
	f := buildFixture(t, originDID, cased)
	_, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), f.head, f.creds, f.docs, bundle.ExportOptions{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "case") {
		t.Fatalf("case-fold colliding DIDs: err=%v, want case-collision rejection", err)
	}
}

// --- verify -----------------------------------------------------------------

func TestVerify_RoundTrip_BothAnchors(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, res := exportFixture(t, f)

	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{
		ExpectedHead:   f.head,
		ExpectedDigest: res.Digest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Result.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall = %v, want Verified (axes %+v)", rep.Result.Overall, rep.Result.Axes)
	}
	if !rep.AnchoredHead || !rep.AnchoredDigest {
		t.Errorf("anchors head=%v digest=%v, want both true", rep.AnchoredHead, rep.AnchoredDigest)
	}
	if rep.Head != f.head || rep.ChainLength != 2 {
		t.Errorf("report head=%s len=%d, want %s/2", rep.Head, rep.ChainLength, f.head)
	}
	if rep.Digest != res.Digest {
		t.Errorf("report digest = %s, want %s", rep.Digest, res.Digest)
	}
}

func TestVerify_NoAnchors_ReportsUnanchored(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.AnchoredHead || rep.AnchoredDigest {
		t.Errorf("anchors head=%v digest=%v, want both false", rep.AnchoredHead, rep.AnchoredDigest)
	}
}

func TestVerify_WrongHeadAnchor(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.origin})
	if !errors.Is(err, bundle.ErrAnchorMismatch) {
		t.Fatalf("wrong head anchor: err=%v, want ErrAnchorMismatch", err)
	}
}

func TestVerify_WrongDigestAnchor(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	wrong := "sha256:" + strings.Repeat("ab", 32)
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedDigest: wrong})
	if !errors.Is(err, bundle.ErrAnchorMismatch) {
		t.Fatalf("wrong digest anchor: err=%v, want ErrAnchorMismatch", err)
	}
}

// mutateJSONFile rewrites one file through a raw JSON map mutation.
func mutateJSONFile(t *testing.T, path string, mutate func(m map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	// decoder-hygiene-exempt: test-side tamper helper on fixture bytes.
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	mutate(m)
	// canonicalizer-hygiene-exempt: deliberate tamper fixture, not a signed artifact.
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestVerify_TamperedCredentialBody(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	mutateJSONFile(t, filepath.Join(dir, "credentials/"+hexOf(f.head)+".json"), func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["outputHash"] = "sha256:" + strings.Repeat("99", 32)
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("tampered body: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_TamperedProofBytes_BodyUnchanged(t *testing.T) {
	// The content address covers the BODY only — replaced proof bytes leave
	// the credential's hash intact and are caught by the files digests
	// (Codex High-2: the machinery that makes the bundle digest cover
	// signatures, not just data flow).
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	mutateJSONFile(t, filepath.Join(dir, "credentials/"+hexOf(f.head)+".json"), func(m map[string]any) {
		proof := m["proof"].(map[string]any)
		proof["proofValue"] = "z3FakeSignatureFakeSignatureFakeSignatureFakeSignature"
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("tampered proof: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_TamperedDIDDocument(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	docPath := filepath.Join(dir, "diddocs", registryID, "did/org/acme/pipeline/p1/process/procA/did.json")
	mutateJSONFile(t, docPath, func(m map[string]any) {
		vms := m["verificationMethod"].([]any)
		vm := vms[0].(map[string]any)
		// A validly-encoded DIFFERENT key: the honest tamper is substitution,
		// not corruption — an undecodable value would fail earlier for a
		// different reason than the signature mismatch this test pins.
		mb, err := did.EncodeEd25519Multikey([]byte(strings.Repeat("k", 32)))
		if err != nil {
			t.Fatal(err)
		}
		vm["publicKeyMultibase"] = mb
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("tampered did doc: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_ListedFileMissing(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	if err := os.Remove(filepath.Join(dir, "credentials/"+hexOf(f.origin)+".json")); err != nil {
		t.Fatal(err)
	}
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("missing listed file: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_UnlistedExtraFile(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	if err := os.WriteFile(filepath.Join(dir, "diddocs", "stray.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("unlisted extra file: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_ManifestChainDivergence(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		m.Chain = []string{m.Chain[1], m.Chain[0]} // reversed
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("manifest chain divergence: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_PredecessorHole_NamedError(t *testing.T) {
	// A consistent attacker removes the origin everywhere except the head's
	// signed link. The rebuild must name the missing predecessor.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	originRel := "credentials/" + hexOf(f.origin) + ".json"
	if err := os.Remove(filepath.Join(dir, originRel)); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		delete(m.Files, originRel)
		m.Chain = m.Chain[1:] // head only
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), f.origin) {
		t.Fatalf("predecessor hole: err=%v, want ErrBundleIntegrity naming %s", err, f.origin)
	}
}

func TestVerify_MissingOwnerDoc_NotVerified(t *testing.T) {
	// Consistently-removed owner document: the bundle is structurally intact
	// but the authority chain cannot terminate — a VERIFICATION outcome
	// (closed world: absence in an archive is definitive), not a structural
	// error. Pins S8 rider (a): signing keys alone are not a usable archive.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	ownerRel := "diddocs/" + registryID + "/did/org/acme/did.json"
	if err := os.Remove(filepath.Join(dir, ownerRel)); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		delete(m.Files, ownerRel)
		kept := m.DIDDocuments[:0]
		for _, d := range m.DIDDocuments {
			if d != ownerDID {
				kept = append(kept, d)
			}
		}
		m.DIDDocuments = kept
	})
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Result.Overall == vc.ConfidenceVerified {
		t.Fatal("chain with no owner document verified — the authority-chain requirement is not enforced offline")
	}
}

// --- review fixes (multi-agent-review 2026-07-06) ----------------------------

func TestVerify_SymlinkedListedFile_Rejected(t *testing.T) {
	// The symlink target holds the CORRECT bytes — the rejection must be for
	// non-regularity itself (an archive holds bytes, not references), not a
	// digest mismatch.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	rel := filepath.Join(dir, "credentials", hexOf(f.head)+".json")
	outside := filepath.Join(t.TempDir(), "outside.json")
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rel); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rel); err != nil {
		t.Fatal(err)
	}
	_, err = bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlinked listed file: err=%v, want ErrBundleIntegrity for a non-regular file", err)
	}
}

func TestVerify_SymlinkedManifest_Rejected(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	real := filepath.Join(dir, "manifest.json")
	outside := filepath.Join(t.TempDir(), "manifest.json")
	b, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, real); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head}); err == nil {
		t.Fatal("symlinked manifest: want error")
	}
}

func TestVerify_SubdirDuplicateCredential_Rejected(t *testing.T) {
	// Two files carrying the same content address but potentially different
	// proof bytes must never race on map order — subdirectory credential
	// entries are structurally invalid.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	src := filepath.Join(dir, "credentials", hexOf(f.origin)+".json")
	dupRel := "credentials/dup/" + hexOf(f.origin) + ".json"
	dupAbs := filepath.Join(dir, filepath.FromSlash(dupRel))
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dupAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dupAbs, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		m.Files[dupRel] = "sha256:" + hex.EncodeToString(sum[:])
	})
	_, err = bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("subdirectory duplicate credential: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_BackslashListedPath_Rejected(t *testing.T) {
	// path.Clean treats `\` as an ordinary byte; on Windows the same string
	// walks out of the bundle. The structural check must reject it on every
	// platform, before any file is opened.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		m.Files[`credentials/..\..\evil.json`] = "sha256:" + strings.Repeat("ab", 32)
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("backslash listed path: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerify_CaseFoldListedPaths_Rejected(t *testing.T) {
	// A case-variant document entry must be rejected by the collision check
	// BEFORE any read: on a case-insensitive filesystem both paths resolve
	// to the same file (its digest would even match), so ordering is the
	// defense being pinned here.
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	lower := "diddocs/" + registryID + "/did/org/acme/pipeline/p1/process/procA/did.json"
	upper := "diddocs/" + registryID + "/did/org/acme/pipeline/p1/process/PROCA/did.json"
	rewriteManifest(t, dir, func(m *bundle.Manifest) {
		m.Files[upper] = m.Files[lower]
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(strings.ToLower(err.Error()), "case") {
		t.Fatalf("case-fold listed paths: err=%v, want ErrBundleIntegrity naming the case collision", err)
	}
}

func TestVerify_UnknownManifestField_Rejected(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir, _ := exportFixture(t, f)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	// decoder-hygiene-exempt: test-side manifest surgery on a fixture the test itself wrote.
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["surprise"] = true
	// canonicalizer-hygiene-exempt: deliberate tamper fixture, not a signed artifact.
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head}); err == nil {
		t.Fatal("unknown manifest field: want error")
	}
}

func TestExportVerify_SingleCredentialChain(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	dir := filepath.Join(t.TempDir(), "b")
	res, err := bundle.Export(context.Background(), dir, f.origin, f.creds, f.docs, bundle.ExportOptions{})
	if err != nil {
		t.Fatalf("Export of a FirstDrop head: %v", err)
	}
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.origin, ExpectedDigest: res.Digest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.ChainLength != 1 || rep.Result.Overall != vc.ConfidenceVerified {
		t.Errorf("len=%d overall=%v, want 1/Verified", rep.ChainLength, rep.Result.Overall)
	}
}

func TestExport_FailedExport_LeavesNoDirectory(t *testing.T) {
	f := buildFixture(t, originDID, childDID)
	parent := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(parent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "bundle") // parent is a file: creation fails
	if _, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{}); err == nil {
		t.Fatal("export under a file parent: want error")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatalf("failed export left %s behind", dir)
	}
}
