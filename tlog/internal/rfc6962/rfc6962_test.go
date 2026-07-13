package rfc6962

import (
	"encoding/hex"
	"testing"
)

// ctLeaves is the classic Certificate Transparency test corpus. The pinned
// roots below are EXTERNAL known answers (the CT reference values,
// cross-generated here by an independent Python RFC 6962 implementation
// before being pinned) — they anchor the scheme against a shared-bug
// round-trip: generation and verification agreeing with each other proves
// nothing if both drift together.
var ctLeaves = func() [][]byte {
	hexes := []string{"", "00", "10", "2021", "3031", "40414243",
		"5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		out[i] = b
	}
	return out
}()

var ctRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // size 0
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func leafHashes(n int) [][HashSize]byte {
	out := make([][HashSize]byte, n)
	for i := 0; i < n; i++ {
		out[i] = LeafHash(ctLeaves[i])
	}
	return out
}

func TestRootKnownAnswers(t *testing.T) {
	for n := 0; n <= len(ctLeaves); n++ {
		if got := hex.EncodeToString(rootOf(n)); got != ctRoots[n] {
			t.Errorf("Root(size %d) = %s, want %s", n, got, ctRoots[n])
		}
	}
}

func rootOf(n int) []byte {
	r := Root(leafHashes(n))
	return r[:]
}

// Every (size, index) inclusion proof the generator emits must verify to the
// generator's root — and to the pinned external root.
func TestInclusionExhaustive(t *testing.T) {
	for n := 1; n <= len(ctLeaves); n++ {
		leaves := leafHashes(n)
		root := Root(leaves)
		for i := uint64(0); i < uint64(n); i++ {
			path := InclusionPath(leaves, i)
			got, err := RootFromInclusion(LeafHash(ctLeaves[i]), i, uint64(n), path)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if got != root {
				t.Errorf("n=%d i=%d: recomputed root mismatch", n, i)
			}
			if hex.EncodeToString(got[:]) != ctRoots[n] {
				t.Errorf("n=%d i=%d: root != external KAT", n, i)
			}
		}
	}
}

// Every 0 < m < n consistency proof must verify to both pinned roots.
func TestConsistencyExhaustive(t *testing.T) {
	for n := 2; n <= len(ctLeaves); n++ {
		leaves := leafHashes(n)
		newRoot := Root(leaves)
		for m := uint64(1); m < uint64(n); m++ {
			oldRoot := Root(leaves[:m])
			path := ConsistencyPath(leaves, m)
			fr, sr, err := RootsFromConsistency(m, uint64(n), oldRoot, path)
			if err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if fr != oldRoot || sr != newRoot {
				t.Errorf("m=%d n=%d: recomputed roots mismatch", m, n)
			}
		}
	}
}

func TestInclusionRejectsMalformedProofs(t *testing.T) {
	leaves := leafHashes(8)
	path := InclusionPath(leaves, 3)
	if _, err := RootFromInclusion(LeafHash(ctLeaves[3]), 3, 8, path[:len(path)-1]); err == nil {
		t.Error("truncated path: want error")
	}
	if _, err := RootFromInclusion(LeafHash(ctLeaves[3]), 3, 8, append(append([][HashSize]byte{}, path...), path[0])); err == nil {
		t.Error("surplus path node: want error")
	}
	if _, err := RootFromInclusion(LeafHash(ctLeaves[3]), 8, 8, path); err == nil {
		t.Error("index == size: want error")
	}
	if _, err := RootFromInclusion(LeafHash(ctLeaves[3]), 0, 0, nil); err == nil {
		t.Error("empty tree: want error")
	}
	// A tampered path must still verify structurally but yield a different
	// root (callers compare against the trusted root).
	tampered := append([][HashSize]byte{}, path...)
	tampered[0][0] ^= 0xff
	got, err := RootFromInclusion(LeafHash(ctLeaves[3]), 3, 8, tampered)
	if err != nil {
		t.Fatalf("tampered path should recompute, not error: %v", err)
	}
	if got == Root(leaves) {
		t.Error("tampered path recomputed the true root")
	}
}

func TestConsistencyRejectsMalformedProofs(t *testing.T) {
	leaves := leafHashes(7)
	old := Root(leaves[:3])
	path := ConsistencyPath(leaves, 3)
	if _, _, err := RootsFromConsistency(3, 7, old, path[:len(path)-1]); err == nil {
		t.Error("truncated path: want error")
	}
	if _, _, err := RootsFromConsistency(3, 7, old, append(append([][HashSize]byte{}, path...), path[0])); err == nil {
		t.Error("surplus path node: want error")
	}
	if _, _, err := RootsFromConsistency(0, 7, old, path); err == nil {
		t.Error("m == 0: want error (degenerate form is the caller's)")
	}
	if _, _, err := RootsFromConsistency(7, 7, old, path); err == nil {
		t.Error("m == n: want error (degenerate form is the caller's)")
	}
	if _, _, err := RootsFromConsistency(3, 7, old, nil); err == nil {
		t.Error("empty path for non-power-of-two m: want error")
	}
}
