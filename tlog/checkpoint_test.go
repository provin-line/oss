package tlog_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/internal/rfc6962"
)

// SignedView is the byte contract every checkpoint signature covers — pinned
// here against a hand-built golden (JCS key order is alphabetical). The
// timestamp is UTC to the second, its one spelling.
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

	// An offset of zero in another location is the same instant, spelled Z.
	zero := *utc
	zero.Timestamp = utc.Timestamp.In(time.FixedZone("UTC0", 0))
	got, err = zero.SignedView()
	if err != nil {
		t.Fatalf("SignedView(zero offset): %v", err)
	}
	if string(got) != wantUTC {
		t.Errorf("zero-offset view:\n got %s\nwant %s", got, wantUTC)
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

// A checkpoint has one spelling of what it signs: its head is in lower case,
// and its timestamp is UTC to the second, as the signed view writes it.
// Anything else is refused, not re-spelled.
func TestSignedView_RefusesAHeadOrTimestampNotInItsOneSpelling(t *testing.T) {
	base := tlog.Checkpoint{Origin: "log", Size: 1, Head: "ab12", Timestamp: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC), SignedBy: "did:x#s"}
	if _, err := base.SignedView(); err != nil {
		t.Fatalf("lower-case head, UTC whole seconds: %v", err)
	}
	for name, set := range map[string]func(*tlog.Checkpoint){
		"head in upper case":     func(c *tlog.Checkpoint) { c.Head = "AB12" },
		"a fraction of a second": func(c *tlog.Checkpoint) { c.Timestamp = c.Timestamp.Add(500 * time.Millisecond) },
		"another offset": func(c *tlog.Checkpoint) {
			c.Timestamp = time.Date(2026, 7, 7, 18, 0, 0, 0, time.FixedZone("JST", 9*3600))
		},
		"an offset with seconds":       func(c *tlog.Checkpoint) { c.Timestamp = c.Timestamp.In(time.FixedZone("", 30)) },
		"a year RFC 3339 cannot write": func(c *tlog.Checkpoint) { c.Timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"a year before zero":           func(c *tlog.Checkpoint) { c.Timestamp = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		c := base
		set(&c)
		if _, err := c.SignedView(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	signer := &tlog.CheckpointSigner{LogID: "log", VerificationMethod: "did:x#s"}
	if _, err := tlog.SignCheckpoint(1, "ab12", signer, time.Date(2026, 7, 7, 18, 0, 0, 0, time.FixedZone("JST", 9*3600))); err == nil {
		t.Error("SignCheckpoint at a time not in UTC: want error")
	}
}

// merkle builds a tree of n leaves and returns its leaf hashes.
func merkle(n int) [][rfc6962.HashSize]byte {
	leaves := make([][rfc6962.HashSize]byte, n)
	for i := range leaves {
		leaves[i] = rfc6962.LeafHash([]byte{byte(i)})
	}
	return leaves
}

func path(p [][rfc6962.HashSize]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = p[i][:]
	}
	return out
}

// Consistency compares heads in their one spelling: under a valid proof, a
// head in upper case is refused, so one root is not equal as bytes and
// unequal as text.
func TestVerifyConsistency_RefusesAHeadNotInLowerCase(t *testing.T) {
	leaves := merkle(3)
	oldRoot, newRoot := rfc6962.Root(leaves[:2]), rfc6962.Root(leaves)
	older := &tlog.Checkpoint{Origin: "a", Size: 2, Head: hex.EncodeToString(oldRoot[:])}
	newer := &tlog.Checkpoint{Origin: "a", Size: 3, Head: hex.EncodeToString(newRoot[:])}
	proof := &tlog.ConsistencyProof{OldSize: 2, NewSize: 3, Path: path(rfc6962.ConsistencyPath(leaves, 2))}
	if err := tlog.VerifyConsistency(older, newer, proof); err != nil {
		t.Fatalf("lower-case heads: %v", err)
	}
	upperOld, upperNew := *older, *newer
	upperOld.Head = strings.ToUpper(older.Head)
	upperNew.Head = strings.ToUpper(newer.Head)
	if err := tlog.VerifyConsistency(&upperOld, newer, proof); err == nil {
		t.Error("older head in upper case: want error")
	}
	if err := tlog.VerifyConsistency(older, &upperNew, proof); err == nil {
		t.Error("newer head in upper case: want error")
	}
}

// Inclusion reads the head in its one spelling too.
func TestVerifyInclusion_RefusesAHeadNotInLowerCase(t *testing.T) {
	leaves := merkle(3)
	root := rfc6962.Root(leaves)
	cp := &tlog.Checkpoint{Origin: "a", Size: 3, Head: hex.EncodeToString(root[:])}
	proof := &tlog.InclusionProof{LeafIndex: 1, TreeSize: 3, Path: path(rfc6962.InclusionPath(leaves, 1))}
	if err := tlog.VerifyInclusion(cp, proof, []byte{1}); err != nil {
		t.Fatalf("lower-case head: %v", err)
	}
	upper := *cp
	upper.Head = strings.ToUpper(cp.Head)
	if err := tlog.VerifyInclusion(&upper, proof, []byte{1}); err == nil {
		t.Error("head in upper case: want error")
	}
}
