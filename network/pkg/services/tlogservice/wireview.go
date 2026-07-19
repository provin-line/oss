package tlogservice

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// OpMirrorLogSegment is the wireauth op name for the MirrorLogSegment RPC —
// it MUST match exactly between the shipper's signed view and the handler's
// verification view (D-T2: every mirror-write RPC carries an L2-style
// wireauth proof signed by the log's writer identity). Namespaced with the
// full RPC identity (mirrors auditor.OpRegisterEvidence's rationale):
// MirrorLogSegment is reached through the L1-authorized TlogService mux, so
// its op name must never collide with another L1-authorized surface's short
// op name.
const OpMirrorLogSegment = "dplaax.tlog.v1.TlogService/MirrorLogSegment"

// MirrorLogSegmentFields builds the exact wireauth signed-view fields for
// one MirrorLogSegment call (spec D-T2): log_id and checkpoint_head
// verbatim, from_index as a decimal string (the value grammar wireauth's
// view accepts — see wireauth.validateFieldValue), and segmentDigest (see
// SegmentDigest). Both the handler (verifying) and the future shipper
// client package (signing) call this SAME builder — the one place that
// keeps the two derivations from drifting.
func MirrorLogSegmentFields(logID string, fromIndex uint64, checkpointHead, segmentDigest string) map[string]any {
	return map[string]any{
		"log_id":          logID,
		"from_index":      strconv.FormatUint(fromIndex, 10),
		"checkpoint_head": checkpointHead,
		"segment_digest":  segmentDigest,
	}
}

// SegmentDigest computes the D-T2 signed-view field that binds a
// MirrorLogSegment segment's payload LIST into the wireauth proof (defense
// in depth alongside the checkpoint-head chain recompute, which commits the
// payloads transitively but only after the store's own tail): sha256 over
// the ORDERED per-record payload hashes.
//
// Exact byte construction: for each payload in order, compute
// sha256(payload) (32 raw bytes); write each 32-byte digest, in order, into
// one running sha256 hasher; the final sum, lowercase-hex-encoded, is the
// segment digest. An empty payloads slice digests to sha256() of zero
// bytes (the well-defined empty-input hash) — a checkpoint resend with no
// new records still has a well-defined, reproducible digest.
//
// This is deliberately NOT the chain-hash formula (tlog.Record.Hash /
// mirrorstore.ChainHash, which folds the PREVIOUS record's hash in): the
// segment digest is a proof-binding hash over exactly this call's payload
// list, independent of the log's prior state, so a signer can compute it
// without first reading the log's current tail.
func SegmentDigest(payloads [][]byte) string {
	h := sha256.New()
	for _, p := range payloads {
		sum := sha256.Sum256(p)
		h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}
