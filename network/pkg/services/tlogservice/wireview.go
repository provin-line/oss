package tlogservice

import "github.com/provin-line/oss/network/pkg/services/tlogservice/wirecontract"

// OpMirrorLogSegment points at wirecontract.OpMirrorLogSegment — moved into
// the leaf wirecontract package (PR3b Task 2) so a client-only consumer need
// not import this service root; this alias keeps existing call sites
// (tlogservice.OpMirrorLogSegment, in the handler and elsewhere) unchanged.
// See wirecontract.OpMirrorLogSegment for the full doc.
const OpMirrorLogSegment = wirecontract.OpMirrorLogSegment

// MirrorLogSegmentFields points at wirecontract.MirrorLogSegmentFields — see
// OpMirrorLogSegment's alias doc.
var MirrorLogSegmentFields = wirecontract.MirrorLogSegmentFields

// SegmentDigest points at wirecontract.SegmentDigest — see
// OpMirrorLogSegment's alias doc.
var SegmentDigest = wirecontract.SegmentDigest

// FrameRecordPayloads points at wirecontract.FrameRecordPayloads — moved
// into the leaf wirecontract package (PR3b Task 2) together with the rest of
// the record_payloads_framed wire codec (see segmentframe.go's history);
// this alias keeps existing call sites unchanged.
var FrameRecordPayloads = wirecontract.FrameRecordPayloads

// UnframeRecordPayloads points at wirecontract.UnframeRecordPayloads — see
// FrameRecordPayloads' alias doc. Used by Service.DecodeSegment (see
// tlogservice.go).
var UnframeRecordPayloads = wirecontract.UnframeRecordPayloads
