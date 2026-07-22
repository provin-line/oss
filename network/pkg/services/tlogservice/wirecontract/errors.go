package wirecontract

import "errors"

// ErrInvalidArgument is tlogservice's general malformed-input sentinel: a
// malformed range parameter, an unparseable log id, a structurally invalid
// MirrorLogSegment request (nil checkpoint, checkpoint.size misaligned,
// from_index/len overflow) — enforced by the tlogservice service root — or,
// via UnframeRecordPayloads in this leaf package, a malformed
// record_payloads_framed blob (a length prefix that overruns the remaining
// bytes, or a malformed varint).
//
// Defined here rather than in the tlogservice service root (PR3b Task 2)
// because UnframeRecordPayloads — the wire framing codec, a
// client/handler-shared concern that must live in this leaf so a
// client-only consumer need not import the service root — has to return the
// SAME sentinel VALUE the rest of tlogservice's domain logic already uses,
// so errors.Is stays intact across both call sites. The leaf cannot instead
// import the root for it (that would recreate the very service-root
// dependency this package exists to avoid); the tlogservice package keeps a
// var alias (see tlogservice.go) so existing call sites are unchanged.
var ErrInvalidArgument = errors.New("tlogservice: invalid argument")

// ErrCapExceeded is the D-T2 rule 5 cap failure: a MirrorLogSegment batch's
// record count or summed byte length exceeds the configured maximum —
// raised by tlogservice.Service.CheckBatchCaps (the shared cap POLICY, owned
// by the service root) AND by UnframeRecordPayloads in this leaf package
// (the SAME policy re-applied at the decode boundary, defense in depth). See
// ErrInvalidArgument's doc for why the sentinel VALUE lives here, with the
// service root aliasing it, rather than the reverse.
var ErrCapExceeded = errors.New("tlogservice: mirror segment: batch exceeds the configured cap")
