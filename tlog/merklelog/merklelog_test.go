package merklelog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/internal/logcontract"
	"github.com/provin-line/oss/tlog/merklelog"
	"github.com/provin-line/oss/vc"
)

func newLog(t *testing.T) *merklelog.Log {
	t.Helper()
	l, err := merklelog.New(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestLogContract(t *testing.T) {
	logcontract.Suite(t, func(t *testing.T) tlog.Log { return newLog(t) })
}

// The classic CT corpus: appending its leaves must reproduce the externally
// pinned RFC 6962 roots (the same anchors the rfc6962 package pins — here
// they prove the LOG wires payloads to the scheme correctly).
var ctLeaves = []string{"", "00", "10", "2021", "3031", "40414243",
	"5051525354555657", "606162636465666768696a6b6c6d6e6f"}

var ctRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

type memKS struct{ keys map[string][]byte }

func (m *memKS) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[did+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKS) GetPrivateKey(did string, keyID keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[did+"#"+string(keyID)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return k, nil
}
func (m *memKS) DeleteKeys(string) error { return nil }

const logID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"

func signedLog(t *testing.T) *merklelog.Log {
	t.Helper()
	ks := &memKS{keys: map[string][]byte{}}
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const signerDID = "did:dplaax:poc.dplaax.dev:org:acme"
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	l, err := merklelog.New(filepath.Join(t.TempDir(), "log"),
		merklelog.WithCheckpointSigner(tlog.CheckpointSigner{
			Signer:             ed25519.NewSigner(ks),
			SignerDID:          signerDID,
			KeyID:              string(keystore.KeyIDSigning),
			VerificationMethod: signerDID + "#signing",
			LogID:              logID,
		}),
		merklelog.WithClock(func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func appendCT(t *testing.T, l *merklelog.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		b, err := hex.DecodeString(ctLeaves[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(context.Background(), b); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}
}

func TestCheckpointHeadMatchesKnownRoots(t *testing.T) {
	l := signedLog(t)
	for n := 0; n <= len(ctLeaves); n++ {
		if n > 0 {
			b, _ := hex.DecodeString(ctLeaves[n-1])
			if _, err := l.Append(context.Background(), b); err != nil {
				t.Fatal(err)
			}
		}
		cp, err := l.Checkpoint(context.Background())
		if err != nil {
			t.Fatalf("Checkpoint(size %d): %v", n, err)
		}
		if cp.Head != ctRoots[n] {
			t.Errorf("size %d: Head = %s, want %s", n, cp.Head, ctRoots[n])
		}
		if cp.Origin != logID {
			t.Errorf("size %d: Origin = %q, want %q", n, cp.Origin, logID)
		}
	}
}

func TestUnsignedCheckpointErrs(t *testing.T) {
	l := newLog(t)
	if _, err := l.Checkpoint(context.Background()); err == nil || !isUnsigned(err) {
		t.Fatalf("Checkpoint without a signer: want wrapped ErrUnsignedLog, got %v", err)
	}
}

func isUnsigned(err error) bool { return errors.Is(err, tlog.ErrUnsignedLog) }

// Every (size, index) proof the log emits verifies through the standalone
// verifiers against the log's own signed checkpoints.
func TestProofsRoundTrip(t *testing.T) {
	ctx := context.Background()
	l := signedLog(t)
	var checkpoints []*tlog.Checkpoint
	cp0, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints = append(checkpoints, cp0)
	for n := 1; n <= len(ctLeaves); n++ {
		b, _ := hex.DecodeString(ctLeaves[n-1])
		if _, err := l.Append(ctx, b); err != nil {
			t.Fatal(err)
		}
		cp, err := l.Checkpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		checkpoints = append(checkpoints, cp)
		for i := uint64(0); i < uint64(n); i++ {
			proof, err := l.ProveInclusion(ctx, i, cp)
			if err != nil {
				t.Fatalf("ProveInclusion(%d, size %d): %v", i, n, err)
			}
			payload, _ := hex.DecodeString(ctLeaves[i])
			if err := tlog.VerifyInclusion(cp, proof, payload); err != nil {
				t.Errorf("VerifyInclusion(%d, size %d): %v", i, n, err)
			}
			if err := tlog.VerifyInclusion(cp, proof, []byte("tampered")); err == nil {
				t.Errorf("VerifyInclusion with the wrong payload verified (i=%d n=%d)", i, n)
			}
		}
	}
	for oi := 0; oi < len(checkpoints); oi++ {
		for ni := oi; ni < len(checkpoints); ni++ {
			older, newer := checkpoints[oi], checkpoints[ni]
			proof, err := l.ProveConsistency(ctx, older, newer)
			if err != nil {
				t.Fatalf("ProveConsistency(%d, %d): %v", older.Size, newer.Size, err)
			}
			if err := tlog.VerifyConsistency(older, newer, proof); err != nil {
				t.Errorf("VerifyConsistency(%d, %d): %v", older.Size, newer.Size, err)
			}
		}
	}
}

func TestProverRefusesForeignCheckpoints(t *testing.T) {
	ctx := context.Background()
	l := signedLog(t)
	appendCT(t, l, 3)
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foreign := *cp
	foreign.Origin = "did:dplaax:poc.dplaax.dev:org:other:pipeline:x"
	if _, err := l.ProveInclusion(ctx, 0, &foreign); err == nil {
		t.Error("ProveInclusion against a foreign-origin checkpoint: want error")
	}
	legacy := *cp
	legacy.Origin = ""
	if _, err := l.ProveInclusion(ctx, 0, &legacy); err == nil {
		t.Error("ProveInclusion against an origin-less checkpoint: want error")
	}
	oversized := *cp
	oversized.Size = 99
	if _, err := l.ProveInclusion(ctx, 0, &oversized); err == nil {
		t.Error("ProveInclusion against a checkpoint larger than the log: want error")
	}
}

// The journal is the source of truth: reopening reproduces the identical
// tree, and a torn final line (a crashed uncommitted append) is truncated
// while committed records survive.
func TestDurabilityAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "log")
	l, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"alpha", "beta", "gamma"} {
		if _, err := l.Append(ctx, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-append: a torn, unterminated tail fragment.
	path := filepath.Join(dir, "leaves.ndjson")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"index":3,"payl`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	re, err := merklelog.New(dir)
	if err != nil {
		t.Fatalf("reopen after torn tail: %v", err)
	}
	defer re.Close()
	if n, _ := re.Size(ctx); n != 3 {
		t.Fatalf("Size after reopen = %d, want 3", n)
	}
	rec, err := re.Get(ctx, 2)
	if err != nil || string(rec.Payload) != "gamma" {
		t.Fatalf("Get(2) after reopen = %v (err %v)", rec, err)
	}
}

// A newline-terminated malformed line is damage, not a crash artifact:
// refuse the open rather than silently truncating history.
func TestReopenRefusesInteriorDamage(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "log")
	l, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	l.Close()
	path := filepath.Join(dir, "leaves.ndjson")
	if err := os.WriteFile(path, []byte("{\"v\":1,\"index\":0,\"payload\":\"garbage\",\"leaf\":\"beef\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := merklelog.New(dir); err == nil {
		t.Fatal("reopen over a rewritten payload/leaf mismatch: want refusal")
	}
}

func TestSingleOpener(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := merklelog.New(dir); err == nil {
		t.Fatal("second live opener: want ErrLocked")
	}
}

// A checkpoint's signature is independently verifiable from the struct
// alone: SignedView reconstructs the signed bytes (Origin included).
func TestCheckpointSignatureVerifiesFromStruct(t *testing.T) {
	ctx := context.Background()
	ks := &memKS{keys: map[string][]byte{}}
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	const signerDID = "did:dplaax:poc.dplaax.dev:org:acme"
	if err := ks.SaveKeyPair(signerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatal(err)
	}
	l, err := merklelog.New(filepath.Join(t.TempDir(), "log"),
		merklelog.WithCheckpointSigner(tlog.CheckpointSigner{
			Signer:             ed25519.NewSigner(ks),
			SignerDID:          signerDID,
			KeyID:              string(keystore.KeyIDSigning),
			VerificationMethod: signerDID + "#signing",
			LogID:              logID,
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(ctx, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := cp.SignedView()
	if err != nil {
		t.Fatalf("SignedView: %v", err)
	}
	ok, err := (ed25519.Verifier{}).Verify(kp.PublicKey, view, cp.Signature)
	if err != nil || !ok {
		t.Errorf("checkpoint signature does not verify over SignedView: ok=%v err=%v", ok, err)
	}
}

// Cross-implementation KAT: vc.ComputeSourceRoot (the source-commitment
// Merkle root) and merklelog implement RFC 6962 independently — feeding the
// log the same leaf bytes in ComputeSourceRoot's sort order (ascending
// sha256 of the canonical wire bytes) must reproduce the digest inside the
// commitment's multihash text (source_root = "f1220" ‖ hex digest). Two
// independent in-repo implementations agreeing on the scheme is the same
// convergence net the conformance vectors use.
func TestCrossKATWithSourceCommitment(t *testing.T) {
	ctx := context.Background()
	var sources []*vc.PipelinePassCredential
	for i, claim := range []vc.TransformationClaim{vc.ClaimConvert, vc.ClaimFilter, vc.ClaimAggregate} {
		cred, err := vc.New(vc.CredentialFields{
			Issuer:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p:process:s",
			ValidFrom: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
			Subject: vc.CredentialSubjectFields{
				PipelineID: "p", ProcessID: "s", TransformationClaim: claim,
				OutputHash: "sha256:" + strings.Repeat(string('1'+byte(i)), 64),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, cred)
	}
	sc, err := vc.NewSourceCommitment(sources, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	// Leaves in ComputeSourceRoot's order: ascending sha256(wire bytes).
	wires := make([][]byte, len(sources))
	for i, s := range sources {
		w, err := s.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = w
	}
	sort.Slice(wires, func(i, j int) bool {
		a, b := sha256.Sum256(wires[i]), sha256.Sum256(wires[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	l := signedLog(t)
	for _, w := range wires {
		if _, err := l.Append(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimPrefix(sc.SourceRoot, "f1220"); cp.Head != want {
		t.Errorf("merklelog root %s != source_root digest %s (independent RFC 6962 implementations diverged)", cp.Head, want)
	}
}

// Regression (Codex P1): appending AFTER a reopen must append, not overwrite
// the journal start — the reopened handle's offset must not matter.
func TestAppendAfterReopen(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "log")
	l, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"alpha", "beta"} {
		if _, err := l.Append(ctx, []byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	re, err := merklelog.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := re.Append(ctx, []byte("gamma")); err != nil {
		t.Fatal(err)
	}
	re.Close()
	final, err := merklelog.New(dir)
	if err != nil {
		t.Fatalf("reopen after post-reopen append: %v (journal corrupted?)", err)
	}
	defer final.Close()
	if n, _ := final.Size(ctx); n != 3 {
		t.Fatalf("Size = %d, want 3", n)
	}
	for i, want := range []string{"alpha", "beta", "gamma"} {
		rec, err := final.Get(ctx, uint64(i))
		if err != nil || string(rec.Payload) != want {
			t.Fatalf("Get(%d) = %q (err %v), want %q", i, rec.Payload, err, want)
		}
	}
}

// Regression (Codex P2): a right-origin in-range checkpoint whose head does
// not commit to this log's state is refused by the Prover.
func TestProverRefusesForeignHead(t *testing.T) {
	ctx := context.Background()
	l := signedLog(t)
	appendCT(t, l, 3)
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	forged := *cp
	forged.Head = strings.Repeat("ab", 32)
	if _, err := l.ProveInclusion(ctx, 0, &forged); err == nil {
		t.Error("ProveInclusion against a foreign head: want error")
	}
	if _, err := l.ProveConsistency(ctx, &forged, cp); err == nil {
		t.Error("ProveConsistency against a foreign head: want error")
	}
}
