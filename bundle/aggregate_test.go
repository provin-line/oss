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
	"sort"
	"strings"
	"testing"

	"github.com/provin-line/oss/bundle"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

const (
	srcADID   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:sensa:process:a1"
	srcBDID   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:sensb:process:b1"
	aggDID    = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:agg:process:g1"
	relayDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:relay:process:r1"
	hashA     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	hashB     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	hashMid   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	hashOut   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	hashAggIn = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
)

// mapConsumed is the test-side ConsumedSetSource.
type mapConsumed struct {
	consumed map[string][]string // agg head hash -> consumed hashes
	sources  map[string][]byte   // consumed hash -> wire bytes
}

func (m mapConsumed) FetchConsumed(_ context.Context, _ string, headHash string) ([]string, error) {
	c, ok := m.consumed[headHash]
	if !ok {
		return nil, fmt.Errorf("no receipt for %s", headHash)
	}
	return c, nil
}

func (m mapConsumed) FetchSourceCredential(_ context.Context, _ string, hash string) ([]byte, error) {
	b, ok := m.sources[hash]
	if !ok {
		return nil, fmt.Errorf("no source %s", hash)
	}
	return b, nil
}

// aggFixture: two source FirstDrops folded by an aggregate FirstDrop whose
// signed body commits to them (real Merkle root), relayed by one chained
// hop — main spine [agg, relay], receipts {agg: [srcA, srcB]}.
type aggFixture struct {
	fixture // embeds creds/docs maps + head/origin of the MAIN spine
	aggHash string
	srcA    string
	srcB    string
	con     mapConsumed
}

func buildAggFixture(t *testing.T) aggFixture {
	t.Helper()
	gen := ed25519.Generator{}
	ks := newMemKeyStore()
	pubs := map[string][]byte{}
	for _, d := range []string{srcADID, srcBDID, aggDID, relayDID} {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.SaveKeyPair(d, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatal(err)
		}
		pubs[d] = kp.PublicKey
	}
	b := vc.NewBuilder(ed25519.NewSigner(ks))

	srcA, err := b.BuildFirstDrop(srcADID, string(keystore.KeyIDSigning), srcADID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "sensa", ProcessID: "a1", TransformationClaim: vc.ClaimConvert, InputHash: hashA, OutputHash: hashA}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srcB, err := b.BuildFirstDrop(srcBDID, string(keystore.KeyIDSigning), srcBDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "sensb", ProcessID: "b1", TransformationClaim: vc.ClaimConvert, InputHash: hashB, OutputHash: hashB}, nil)
	if err != nil {
		t.Fatal(err)
	}

	sources := []*vc.PipelinePassCredential{srcA, srcB}
	root, err := vc.ComputeSourceRoot(sources, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatalf("ComputeSourceRoot: %v", err)
	}
	issuers := []string{srcADID, srcBDID}
	sort.Strings(issuers)
	agg, err := b.BuildFirstDrop(aggDID, string(keystore.KeyIDSigning), aggDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "agg", ProcessID: "g1", TransformationClaim: vc.ClaimAggregate, OutputHash: hashAggIn},
		&vc.SourceCommitment{DerivedFrom: issuers, SourceRoot: root, SourceRootCanonical: vc.SourceRootCanonicalJCS})
	if err != nil {
		t.Fatalf("aggregate BuildFirstDrop: %v", err)
	}
	relay, err := b.BuildChainPreserving(relayDID, string(keystore.KeyIDSigning), relayDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "relay", ProcessID: "r1", TransformationClaim: vc.ClaimConvert, InputHash: hashAggIn, OutputHash: hashOut},
		agg, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := aggFixture{fixture: fixture{creds: mapCredSource{}, docs: mapDocSource{}}, con: mapConsumed{consumed: map[string][]string{}, sources: map[string][]byte{}}}
	for _, c := range []*vc.PipelinePassCredential{agg, relay} {
		h, _ := c.Hash()
		raw, _ := c.MarshalJSON()
		f.creds[h] = raw
	}
	f.aggHash, _ = agg.Hash()
	f.head, _ = relay.Hash()
	aHash, _ := srcA.Hash()
	bHash, _ := srcB.Hash()
	rawA, _ := srcA.MarshalJSON()
	rawB, _ := srcB.MarshalJSON()
	f.srcA, f.srcB = aHash, bHash
	consumed := []string{aHash, bHash}
	sort.Strings(consumed)
	f.con.consumed[f.aggHash] = consumed
	f.con.sources[aHash] = rawA
	f.con.sources[bHash] = rawB

	for d, pub := range pubs {
		f.docs[d] = didDoc(t, d, ownerDID, pub)
	}
	f.docs[ownerDID] = didDoc(t, ownerDID, ownerDID, nil)
	return f
}

func exportAggComplete(t *testing.T, f aggFixture) (string, *bundle.ExportResult) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "b")
	res, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{
		AggregateComplete: true,
		Consumed:          f.con,
	})
	if err != nil {
		t.Fatalf("aggregate-complete Export: %v", err)
	}
	return dir, res
}

func TestAggregateComplete_ExportAndVerifyRoundTrip(t *testing.T) {
	f := buildAggFixture(t)
	dir, res := exportAggComplete(t, f)

	m := res.Manifest
	if m.V != 2 || m.Scope != bundle.ScopeAggregateComplete {
		t.Fatalf("manifest v=%d scope=%q, want 2/%s", m.V, m.Scope, bundle.ScopeAggregateComplete)
	}
	if got := m.Receipts[f.aggHash]; len(got) != 2 || got[0] != f.con.consumed[f.aggHash][0] {
		t.Fatalf("manifest receipts = %v, want the folded set", m.Receipts)
	}
	if len(m.Chain) != 2 || m.Chain[0] != f.aggHash || m.Chain[1] != f.head {
		t.Fatalf("main chain = %v, want [agg relay]", m.Chain)
	}

	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head, ExpectedDigest: res.Digest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Result.Overall != vc.ConfidenceVerified {
		t.Fatalf("Overall = %v (axes %+v), want Verified", rep.Result.Overall, rep.Result.Axes)
	}
	if rep.Scope != bundle.ScopeAggregateComplete || rep.Aggregates != 1 || rep.Sources != 2 {
		t.Fatalf("report scope=%q aggregates=%d sources=%d, want aggregate-complete/1/2", rep.Scope, rep.Aggregates, rep.Sources)
	}
}

// The linear path is untouched: same head without the flag yields the
// shipped v1 shape, and its report claims only linear coverage.
func TestAggregateComplete_LinearPathUnchanged(t *testing.T) {
	f := buildAggFixture(t)
	dir := filepath.Join(t.TempDir(), "b")
	res, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{})
	if err != nil {
		t.Fatalf("linear Export: %v", err)
	}
	if res.Manifest.V != 1 || res.Manifest.Scope != bundle.ScopeLinear || res.Manifest.Receipts != nil {
		t.Fatalf("linear manifest = v%d %q receipts=%v, want the shipped v1 shape", res.Manifest.V, res.Manifest.Scope, res.Manifest.Receipts)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "receipts") {
		t.Fatal("v1 manifest bytes must not mention receipts at all")
	}
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if err != nil {
		t.Fatalf("v1 verify: %v", err)
	}
	if rep.Scope != bundle.ScopeLinear {
		t.Fatalf("v1 verify scope = %q, want linear", rep.Scope)
	}
}

// A v1 manifest smuggling a receipts member is rejected by construction
// (per-version exact wire structs — Codex Med-1).
func TestVerify_V1ManifestWithReceipts_Rejected(t *testing.T) {
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
	m["receipts"] = map[string]any{}
	// canonicalizer-hygiene-exempt: deliberate tamper fixture.
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head}); err == nil {
		t.Fatal("v1 manifest carrying receipts: want rejection")
	}
}

// A commitment-bearing aggregate without a receipts entry must fail — the
// offline analog of "no silent linear-only downgrade".
func TestVerifyV2_MissingReceiptEntry(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		m["receipts"] = map[string]any{}
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("missing receipt entry: err=%v, want ErrBundleIntegrity", err)
	}
}

// A consistent lying receipt (subset, with the dropped source file removed
// everywhere) cannot fake a Verified: the recomputed root cannot match the
// signed commitment (missing claimed issuer → not Verified).
func TestVerifyV2_LyingSubsetReceipt_NotVerified(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	dropRel := "credentials/" + strings.TrimPrefix(f.srcB, "sha256:") + ".json"
	if err := os.Remove(filepath.Join(dir, dropRel)); err != nil {
		t.Fatal(err)
	}
	rewriteManifestV2(t, dir, func(m map[string]any) {
		delete(m["files"].(map[string]any), dropRel)
		m["receipts"].(map[string]any)[f.aggHash] = []any{f.srcA}
	})
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if err != nil {
		t.Fatalf("Verify (structural should pass, verdict should fail): %v", err)
	}
	if rep.Result.Overall == vc.ConfidenceVerified {
		t.Fatal("a subset receipt produced a Verified verdict — the signed root recomputation is not gating")
	}
}

// A receipt entry with duplicates is malformed evidence.
func TestVerifyV2_DuplicateReceiptEntry(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		m["receipts"].(map[string]any)[f.aggHash] = []any{f.srcA, f.srcA, f.srcB}
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("duplicate receipt entry: err=%v, want ErrBundleIntegrity", err)
	}
}

// Export fails loudly when the emit-locus receipt is unavailable.
func TestExportAggregateComplete_MissingReceiptFailsExport(t *testing.T) {
	f := buildAggFixture(t)
	delete(f.con.consumed, f.aggHash)
	_, err := bundle.Export(context.Background(), filepath.Join(t.TempDir(), "b"), f.head, f.creds, f.docs, bundle.ExportOptions{
		AggregateComplete: true, Consumed: f.con,
	})
	if err == nil {
		t.Fatal("aggregate-complete export without the emit-locus receipt: want error")
	}
}

// A chain-preserving credential carrying a commitment over its predecessor
// needs NO receipt: the predecessor is already in the bundle
// (all-consumed semantics) — pinned so the shape the library permits stays
// exportable (Codex High-1).
func TestAggregateComplete_ChainPreservingCommitment(t *testing.T) {
	gen := ed25519.Generator{}
	ks := newMemKeyStore()
	pubs := map[string][]byte{}
	for _, d := range []string{srcADID, relayDID} {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		_ = ks.SaveKeyPair(d, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp})
		pubs[d] = kp.PublicKey
	}
	b := vc.NewBuilder(ed25519.NewSigner(ks))
	origin, err := b.BuildFirstDrop(srcADID, string(keystore.KeyIDSigning), srcADID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "sensa", ProcessID: "a1", TransformationClaim: vc.ClaimConvert, InputHash: hashA, OutputHash: hashMid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := vc.ComputeSourceRoot([]*vc.PipelinePassCredential{origin}, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	head, err := b.BuildChainPreserving(relayDID, string(keystore.KeyIDSigning), relayDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "relay", ProcessID: "r1", TransformationClaim: vc.ClaimConvert, InputHash: hashMid, OutputHash: hashOut},
		origin, &vc.SourceCommitment{DerivedFrom: []string{srcADID}, SourceRoot: root, SourceRootCanonical: vc.SourceRootCanonicalJCS})
	if err != nil {
		t.Fatalf("chain-preserving with commitment: %v", err)
	}

	f := fixture{creds: mapCredSource{}, docs: mapDocSource{}}
	for _, c := range []*vc.PipelinePassCredential{origin, head} {
		h, _ := c.Hash()
		raw, _ := c.MarshalJSON()
		f.creds[h] = raw
	}
	f.head, _ = head.Hash()
	for d, pub := range pubs {
		f.docs[d] = didDoc(t, d, ownerDID, pub)
	}
	f.docs[ownerDID] = didDoc(t, ownerDID, ownerDID, nil)

	dir := filepath.Join(t.TempDir(), "b")
	res, err := bundle.Export(context.Background(), dir, f.head, f.creds, f.docs, bundle.ExportOptions{
		AggregateComplete: true, Consumed: mapConsumed{consumed: map[string][]string{}, sources: map[string][]byte{}},
	})
	if err != nil {
		t.Fatalf("export with a chain-preserving commitment: %v", err)
	}
	if len(res.Manifest.Receipts) != 0 {
		t.Fatalf("receipts = %v, want none (the predecessor is the source)", res.Manifest.Receipts)
	}
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head, ExpectedDigest: res.Digest})
	if err != nil || rep.Result.Overall != vc.ConfidenceVerified {
		t.Fatalf("verify = %+v (err %v), want Verified", rep, err)
	}
	if rep.Aggregates != 1 || rep.Sources != 1 {
		t.Fatalf("report aggregates=%d sources=%d, want 1/1 (the predecessor-committed hop)", rep.Aggregates, rep.Sources)
	}
}

// rewriteManifestV2 mutates the raw manifest map (consistent-attacker
// helper; digest anchors deliberately broken).
func rewriteManifestV2(t *testing.T, dir string, mutate func(m map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	// decoder-hygiene-exempt: test-side manifest surgery on a fixture the test itself wrote.
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	// canonicalizer-hygiene-exempt: deliberate tamper fixture.
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Nested aggregates (an aggregate whose consumed source is itself an
// aggregate) exercise the classification queue's recursion — the trickiest
// walk path, pinned end to end.
func TestAggregateComplete_NestedAggregates(t *testing.T) {
	gen := ed25519.Generator{}
	ks := newMemKeyStore()
	pubs := map[string][]byte{}
	const innerAggDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:inner:process:i1"
	for _, d := range []string{srcADID, innerAggDID, aggDID} {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		_ = ks.SaveKeyPair(d, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp})
		pubs[d] = kp.PublicKey
	}
	b := vc.NewBuilder(ed25519.NewSigner(ks))
	srcX, err := b.BuildFirstDrop(srcADID, string(keystore.KeyIDSigning), srcADID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "sensa", ProcessID: "a1", TransformationClaim: vc.ClaimConvert, InputHash: hashA, OutputHash: hashA}, nil)
	if err != nil {
		t.Fatal(err)
	}
	innerRoot, err := vc.ComputeSourceRoot([]*vc.PipelinePassCredential{srcX}, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := b.BuildFirstDrop(innerAggDID, string(keystore.KeyIDSigning), innerAggDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "inner", ProcessID: "i1", TransformationClaim: vc.ClaimAggregate, OutputHash: hashMid},
		&vc.SourceCommitment{DerivedFrom: []string{srcADID}, SourceRoot: innerRoot, SourceRootCanonical: vc.SourceRootCanonicalJCS})
	if err != nil {
		t.Fatal(err)
	}
	outerRoot, err := vc.ComputeSourceRoot([]*vc.PipelinePassCredential{inner}, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := b.BuildFirstDrop(aggDID, string(keystore.KeyIDSigning), aggDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "agg", ProcessID: "g1", TransformationClaim: vc.ClaimAggregate, OutputHash: hashOut},
		&vc.SourceCommitment{DerivedFrom: []string{innerAggDID}, SourceRoot: outerRoot, SourceRootCanonical: vc.SourceRootCanonicalJCS})
	if err != nil {
		t.Fatal(err)
	}

	f := aggFixture{fixture: fixture{creds: mapCredSource{}, docs: mapDocSource{}}, con: mapConsumed{consumed: map[string][]string{}, sources: map[string][]byte{}}}
	outerHash, _ := outer.Hash()
	innerHash, _ := inner.Hash()
	srcHash, _ := srcX.Hash()
	rawOuter, _ := outer.MarshalJSON()
	rawInner, _ := inner.MarshalJSON()
	rawSrc, _ := srcX.MarshalJSON()
	f.creds[outerHash] = rawOuter
	f.head = outerHash
	f.con.consumed[outerHash] = []string{innerHash}
	f.con.consumed[innerHash] = []string{srcHash}
	f.con.sources[innerHash] = rawInner
	f.con.sources[srcHash] = rawSrc
	for d, pub := range pubs {
		f.docs[d] = didDoc(t, d, ownerDID, pub)
	}
	f.docs[ownerDID] = didDoc(t, ownerDID, ownerDID, nil)

	dir, res := exportAggComplete(t, f)
	if len(res.Manifest.Receipts) != 2 {
		t.Fatalf("receipts = %v, want entries for BOTH aggregates (nested classification)", res.Manifest.Receipts)
	}
	rep, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head, ExpectedDigest: res.Digest})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Result.Overall != vc.ConfidenceVerified || rep.Aggregates != 2 || rep.Sources != 2 {
		t.Fatalf("nested verify = overall %v aggregates=%d sources=%d, want Verified/2/2", rep.Result.Overall, rep.Aggregates, rep.Sources)
	}
}

// A spineless extra credential is an integrity error under the union rule —
// including via a self-referential receipt, which must not mint a
// credential its own "spine" (Claude Minor-4).
func TestVerifyV2_SpinelessCredential_UnionRule(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	// Craft an extra credential file unreachable from any spine.
	extra := buildFixture(t, originDID, childDID)
	extraRel := "credentials/" + hexOf(extra.origin) + ".json"
	raw := []byte(extra.creds[extra.origin])
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(extraRel)), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		m["files"].(map[string]any)[extraRel] = "sha256:" + hex.EncodeToString(sum[:])
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), "no spine") {
		t.Fatalf("spineless extra credential: err=%v, want union-rule integrity error", err)
	}
}

func TestVerifyV2_SelfReferentialReceipt(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		m["receipts"].(map[string]any)[f.aggHash] = []any{f.aggHash}
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("self-referential receipt: err=%v, want integrity error", err)
	}
}

func TestVerifyV2_ReceiptForChainPreserving_Rejected(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		// f.head is the chain-preserving relay (no commitment): a receipts
		// entry for it is malformed evidence.
		m["receipts"].(map[string]any)[f.head] = []any{f.srcA}
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) {
		t.Fatalf("receipt for a non-aggregate-shaped credential: err=%v, want ErrBundleIntegrity", err)
	}
}

func TestVerifyV2_UnsortedReceipt_Rejected(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		entry := m["receipts"].(map[string]any)[f.aggHash].([]any)
		entry[0], entry[1] = entry[1], entry[0]
		m["receipts"].(map[string]any)[f.aggHash] = entry
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), "ascending") {
		t.Fatalf("unsorted receipt: err=%v, want strictly-ascending integrity error", err)
	}
}

func TestVerifyV2_EmptyReceiptEntry_Rejected(t *testing.T) {
	f := buildAggFixture(t)
	dir, _ := exportAggComplete(t, f)
	rewriteManifestV2(t, dir, func(m map[string]any) {
		m["receipts"].(map[string]any)[f.aggHash] = []any{}
	})
	_, err := bundle.Verify(context.Background(), dir, bundle.VerifyOptions{ExpectedHead: f.head})
	if !errors.Is(err, bundle.ErrBundleIntegrity) || !strings.Contains(err.Error(), "never empty") {
		t.Fatalf("empty receipt entry: err=%v, want integrity error", err)
	}
}
