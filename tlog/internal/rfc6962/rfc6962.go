// Package rfc6962 is the pinned Merkle tree-hashing scheme for tree logs:
// RFC 6962 over SHA-256 (leaf prefix 0x00, interior prefix 0x01, MTH with
// odd-subtree promotion, empty root = SHA-256("")), plus the proof
// generation (RFC 6962 §2.1.1/§2.1.2) and verification (RFC 9162
// §2.1.3.2/§2.1.4.2) algorithms. The scheme is v0-frozen — changing any of
// it breaks proof compatibility across implementations (next MAJOR).
//
// Generation operates over the full leaf-hash slice a log holds;
// verification is pure over (hashes, sizes, path) so a third party needs no
// log access. The two sides are exercised against each other exhaustively
// and against external known-answer roots in the tests.
package rfc6962

import (
	"crypto/sha256"
	"errors"
)

// HashSize is the byte length of every hash in the scheme.
const HashSize = sha256.Size

// LeafHash is SHA-256(0x00 ‖ payload).
func LeafHash(payload []byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(payload)
	var out [HashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash is SHA-256(0x01 ‖ left ‖ right).
func NodeHash(left, right [HashSize]byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [HashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Root is MTH over precomputed leaf hashes; the empty tree's root is
// SHA-256("") (RFC 6962 §2.1).
func Root(leaves [][HashSize]byte) [HashSize]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return NodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// splitPoint is the largest power of two strictly less than n (n >= 2).
func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// InclusionPath is PATH(m, D[n]) (RFC 6962 §2.1.1): the audit path for the
// leaf at index m in the tree over leaves.
func InclusionPath(leaves [][HashSize]byte, m uint64) [][HashSize]byte {
	n := uint64(len(leaves))
	if n <= 1 {
		return nil
	}
	k := uint64(splitPoint(int(n)))
	if m < k {
		return append(InclusionPath(leaves[:k], m), Root(leaves[k:]))
	}
	return append(InclusionPath(leaves[k:], m-k), Root(leaves[:k]))
}

// ConsistencyPath is PROOF(m, D[n]) (RFC 6962 §2.1.2): the consistency proof
// between the tree over leaves[:m] and the tree over all leaves.
// Callers must pass 0 < m <= len(leaves); m == 0 has no path form (the
// degenerate vacuous-prefix case is the caller's, mirroring the verifier).
func ConsistencyPath(leaves [][HashSize]byte, m uint64) [][HashSize]byte {
	if m == 0 || m > uint64(len(leaves)) {
		panic("rfc6962: ConsistencyPath requires 0 < m <= len(leaves)")
	}
	return subProof(m, leaves, true)
}

func subProof(m uint64, d [][HashSize]byte, b bool) [][HashSize]byte {
	n := uint64(len(d))
	if m == n {
		if b {
			return nil
		}
		return [][HashSize]byte{Root(d)}
	}
	k := uint64(splitPoint(int(n)))
	if m <= k {
		return append(subProof(m, d[:k], b), Root(d[k:]))
	}
	return append(subProof(m-k, d[k:], false), Root(d[:k]))
}

// Verification errors. Path over/underrun are distinct so a caller's error
// text names the actual malformation.
var (
	ErrEmptyTree     = errors.New("rfc6962: inclusion in an empty tree")
	ErrIndexRange    = errors.New("rfc6962: leaf index out of range")
	ErrPathTooLong   = errors.New("rfc6962: proof path longer than the tree admits")
	ErrPathTooShort  = errors.New("rfc6962: proof path exhausted before the root")
	ErrSizeOrder     = errors.New("rfc6962: consistency sizes out of order")
	ErrEmptyPath     = errors.New("rfc6962: empty consistency path")
	ErrSizeUndefined = errors.New("rfc6962: consistency from size zero has no path form")
)

// RootFromInclusion recomputes the root that (leaf, index, size, path)
// commits to (RFC 9162 §2.1.3.2). The caller compares it to a trusted root.
func RootFromInclusion(leaf [HashSize]byte, index, size uint64, path [][HashSize]byte) ([HashSize]byte, error) {
	var zero [HashSize]byte
	if size == 0 {
		return zero, ErrEmptyTree
	}
	if index >= size {
		return zero, ErrIndexRange
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return zero, ErrPathTooLong
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return zero, ErrPathTooShort
	}
	return r, nil
}

// RootsFromConsistency recomputes the (older, newer) roots a consistency
// path commits to for 0 < m < n (RFC 9162 §2.1.4.2), anchored at oldRoot
// (needed when m is an exact power of two, where the path omits the old
// root). The caller compares both against its trusted checkpoints; the
// m == 0 and m == n degenerate forms are the caller's to define.
func RootsFromConsistency(m, n uint64, oldRoot [HashSize]byte, path [][HashSize]byte) (fr, sr [HashSize]byte, err error) {
	var zero [HashSize]byte
	if m == 0 {
		return zero, zero, ErrSizeUndefined
	}
	if m >= n {
		return zero, zero, ErrSizeOrder
	}
	// Deliberate deviation from RFC 9162 step ordering: the empty-path check
	// runs AFTER the power-of-two prepend; an empty input path still rejects
	// (sn >= 1 forces ErrPathTooShort), only the error identity differs.
	full := path
	if m&(m-1) == 0 { // m is an exact power of two: the old root anchors the walk
		full = append([][HashSize]byte{oldRoot}, path...)
	}
	if len(full) == 0 {
		return zero, zero, ErrEmptyPath
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr = full[0], full[0]
	for _, c := range full[1:] {
		if sn == 0 {
			return zero, zero, ErrPathTooLong
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return zero, zero, ErrPathTooShort
	}
	return fr, sr, nil
}
