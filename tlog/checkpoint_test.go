package tlog_test

import (
	"testing"
	"time"

	"github.com/provin-line/oss/tlog"
)

// SignedView is the byte contract every checkpoint signature covers — pinned
// here against hand-built goldens (JCS key order is alphabetical). Two
// timestamps are pinned: UTC and a zoned offset — the view does NOT
// normalize to UTC, and a UTC-only golden could not detect an accidental
// normalization creeping in.
func TestSignedViewGolden(t *testing.T) {
	utc := &tlog.Checkpoint{
		Origin:    "did:x:pipeline:p",
		Size:      42,
		Head:      "headhash",
		Timestamp: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		SignedBy:  "did:x#signing",
	}
	wantUTC := `{"head":"headhash","logId":"did:x:pipeline:p","purpose":"dplaax-tlog-checkpoint","signedBy":"did:x#signing","size":"42","timestamp":"2026-07-07T09:00:00Z","v":1}`
	got, err := utc.SignedView()
	if err != nil {
		t.Fatalf("SignedView: %v", err)
	}
	if string(got) != wantUTC {
		t.Errorf("UTC view:\n got %s\nwant %s", got, wantUTC)
	}

	zoned := *utc
	zoned.Timestamp = time.Date(2026, 7, 7, 18, 0, 0, 0, time.FixedZone("JST", 9*3600))
	wantZoned := `{"head":"headhash","logId":"did:x:pipeline:p","purpose":"dplaax-tlog-checkpoint","signedBy":"did:x#signing","size":"42","timestamp":"2026-07-07T18:00:00+09:00","v":1}`
	got, err = zoned.SignedView()
	if err != nil {
		t.Fatalf("SignedView(zoned): %v", err)
	}
	if string(got) != wantZoned {
		t.Errorf("zoned view (must NOT be normalized to UTC):\n got %s\nwant %s", got, wantZoned)
	}
}

// Fail-closed: a legacy checkpoint (no Origin) or a signer-less one never
// yields a view with blank identity fields.
func TestSignedViewFailsClosed(t *testing.T) {
	var nilCP *tlog.Checkpoint
	if _, err := nilCP.SignedView(); err == nil {
		t.Error("nil checkpoint: want error")
	}
	legacy := &tlog.Checkpoint{Size: 1, Head: "h", SignedBy: "did:x#s"}
	if _, err := legacy.SignedView(); err == nil {
		t.Error("empty Origin (legacy checkpoint): want error")
	}
	unsigned := &tlog.Checkpoint{Origin: "log", Size: 1, Head: "h"}
	if _, err := unsigned.SignedView(); err == nil {
		t.Error("empty SignedBy: want error")
	}
}

// VerifyConsistency's origin rules: checkpoints of different logs are not
// comparable, and origin-less checkpoints are rejected, not guessed about.
// (The RFC 6962 math itself is pinned in internal/rfc6962 and exercised
// end-to-end by merklelog's round-trip tests.)
func TestVerifyConsistencyOriginRules(t *testing.T) {
	mk := func(origin string, size uint64, head string) *tlog.Checkpoint {
		return &tlog.Checkpoint{Origin: origin, Size: size, Head: head}
	}
	empty := &tlog.ConsistencyProof{OldSize: 0, NewSize: 3}
	if err := tlog.VerifyConsistency(mk("a", 0, "x"), mk("b", 3, "y"), empty); err == nil {
		t.Error("different origins: want error")
	}
	if err := tlog.VerifyConsistency(mk("", 0, "x"), mk("", 3, "y"), empty); err == nil {
		t.Error("empty origins: want error")
	}
	if err := tlog.VerifyConsistency(mk("a", 0, "x"), mk("a", 3, "y"), empty); err != nil {
		t.Errorf("vacuous prefix (old size 0, empty path): %v", err)
	}
	if err := tlog.VerifyConsistency(mk("a", 0, "x"), mk("a", 3, "y"),
		&tlog.ConsistencyProof{OldSize: 0, NewSize: 3, Path: [][]byte{make([]byte, 32)}}); err == nil {
		t.Error("old size 0 with a non-empty path: want error")
	}
	same := &tlog.ConsistencyProof{OldSize: 2, NewSize: 2}
	if err := tlog.VerifyConsistency(mk("a", 2, "h"), mk("a", 2, "h"), same); err != nil {
		t.Errorf("equal sizes, equal heads, empty path: %v", err)
	}
	if err := tlog.VerifyConsistency(mk("a", 2, "h1"), mk("a", 2, "h2"), same); err == nil {
		t.Error("equal sizes with different heads: want error")
	}
	if err := tlog.VerifyConsistency(mk("a", 3, "x"), mk("a", 2, "y"),
		&tlog.ConsistencyProof{OldSize: 3, NewSize: 2}); err == nil {
		t.Error("older larger than newer: want error")
	}
	if err := tlog.VerifyConsistency(mk("a", 1, "x"), mk("a", 3, "y"),
		&tlog.ConsistencyProof{OldSize: 2, NewSize: 3}); err == nil {
		t.Error("proof sizes disagreeing with checkpoint sizes: want error")
	}
}

// VerifyInclusion rejection rules (§2.5), table-driven.
func TestVerifyInclusionRejectionRules(t *testing.T) {
	good := &tlog.Checkpoint{Origin: "a", Size: 1,
		Head: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"}
	proof := &tlog.InclusionProof{LeafIndex: 0, TreeSize: 1}
	if err := tlog.VerifyInclusion(good, proof, []byte{}); err != nil {
		t.Fatalf("size-1 tree, empty payload leaf: %v", err)
	}
	for name, tc := range map[string]struct {
		cp    *tlog.Checkpoint
		proof *tlog.InclusionProof
	}{
		"nil checkpoint": {nil, proof},
		"nil proof":      {good, nil},
		"size mismatch":  {good, &tlog.InclusionProof{LeafIndex: 0, TreeSize: 2}},
		"bad head hex":   {&tlog.Checkpoint{Origin: "a", Size: 1, Head: "zz"}, proof},
		"short head":     {&tlog.Checkpoint{Origin: "a", Size: 1, Head: "abcd"}, proof},
		"short path element": {good, &tlog.InclusionProof{LeafIndex: 0, TreeSize: 1,
			Path: [][]byte{{1, 2, 3}}}},
	} {
		if err := tlog.VerifyInclusion(tc.cp, tc.proof, []byte{}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
