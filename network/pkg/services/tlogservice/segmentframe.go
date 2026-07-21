package tlogservice

import (
	"encoding/binary"
	"fmt"
)

// FrameRecordPayloads encodes an ordered list of record payloads into the
// MirrorLogSegmentRequest.record_payloads_framed wire blob: for each payload
// in order, an unsigned varint of its byte length followed by the payload
// bytes, concatenated. An empty list encodes to an empty blob. Exact inverse
// of UnframeRecordPayloads.
//
// The framed shape (one bytes field) replaces the original repeated-bytes
// field so the registry decodes a whole segment as ONE allocation the size of
// the wire blob. A repeated-bytes field decodes each element into its own
// 24-byte slice header, so a ~9 MiB request of millions of zero-length
// elements amplifies into ~100 MiB — and Connect does that decode BEFORE the
// caps or the wireauth proof run (the L1 interceptor receives an
// already-unmarshalled message). With framing, UnframeRecordPayloads bounds
// the record count/bytes DURING the scan, so the decoded [][]byte is bounded
// by the caps, not by the wire size.
func FrameRecordPayloads(payloads [][]byte) []byte {
	total := 0
	var lb [binary.MaxVarintLen64]byte
	for _, p := range payloads {
		total += binary.PutUvarint(lb[:], uint64(len(p))) + len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range payloads {
		n := binary.PutUvarint(lb[:], uint64(len(p)))
		out = append(out, lb[:n]...)
		out = append(out, p...)
	}
	return out
}

// UnframeRecordPayloads decodes a record_payloads_framed blob back into the
// ordered payload list, enforcing the D-T2 caps DURING the scan: it never
// accumulates more than maxRecords payloads or more than maxBytes summed
// payload bytes — the moment either would be exceeded it returns ErrCapExceeded,
// so a hostile blob can never force an unbounded [][]byte (the reshape's whole
// point). A length prefix that overruns the remaining bytes, or a malformed
// varint, is ErrInvalidArgument.
//
// Each returned payload ALIASES data (no copy) — the caller owns the blob for
// the life of the call, and the durable store copies payloads into its own
// journal. maxRecords and maxBytes MUST be positive (a non-positive cap is a
// caller/config bug, surfaced as an error rather than silently admitting
// everything).
func UnframeRecordPayloads(data []byte, maxRecords, maxBytes int) ([][]byte, error) {
	if maxRecords <= 0 || maxBytes <= 0 {
		return nil, fmt.Errorf("%w: UnframeRecordPayloads: non-positive caps (maxRecords=%d maxBytes=%d)", ErrInvalidArgument, maxRecords, maxBytes)
	}
	var out [][]byte
	totalBytes := 0
	for len(data) > 0 {
		if len(out) == maxRecords {
			return nil, fmt.Errorf("%w: more than max-batch-records %d records", ErrCapExceeded, maxRecords)
		}
		n, adv := binary.Uvarint(data)
		if adv <= 0 {
			return nil, fmt.Errorf("%w: malformed record length varint (%d bytes remaining)", ErrInvalidArgument, len(data))
		}
		data = data[adv:]
		if uint64(len(data)) < n {
			return nil, fmt.Errorf("%w: record length %d overruns %d remaining bytes", ErrInvalidArgument, n, len(data))
		}
		// n <= len(data) (checked above), so int(n) is in range.
		totalBytes += int(n)
		if totalBytes > maxBytes {
			return nil, fmt.Errorf("%w: more than max-batch-bytes %d bytes", ErrCapExceeded, maxBytes)
		}
		// Three-index slice: cap==len so a downstream append on a returned
		// payload can never clobber the following frame's bytes in the shared
		// blob (the payloads alias data; the store copies them into its own
		// journal, but a caller must not be able to reach past its own record).
		out = append(out, data[:n:n])
		data = data[n:]
	}
	return out, nil
}
