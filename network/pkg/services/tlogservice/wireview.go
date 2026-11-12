package tlogservice

import "github.com/provin-line/oss/network/pkg/services/tlogservice/wirecontract"

// OpMirrorLogSegment points at wirecontract.OpMirrorLogSegment — defined in
// the leaf wirecontract package so a client-only consumer need
// not import this service root; this alias keeps existing call sites
// (tlogservice.OpMirrorLogSegment, in the handler and elsewhere) unchanged.
// See wirecontract.OpMirrorLogSegment for the full doc.
const OpMirrorLogSegment = wirecontract.OpMirrorLogSegment

// MirrorLogSegmentFields calls wirecontract.MirrorLogSegmentFields — see
// OpMirrorLogSegment's doc.
func MirrorLogSegmentFields(logID string, fromIndex uint64, checkpointHead, segmentDigest string) map[string]any {
	return wirecontract.MirrorLogSegmentFields(logID, fromIndex, checkpointHead, segmentDigest)
}

// SegmentDigest calls wirecontract.SegmentDigest — see
// OpMirrorLogSegment's doc.
func SegmentDigest(payloads [][]byte) string {
	return wirecontract.SegmentDigest(payloads)
}

// FrameRecordPayloads calls wirecontract.FrameRecordPayloads — defined
// in the leaf wirecontract package together with the rest of
// the record_payloads_framed wire codec;
// this keeps existing call sites unchanged.
func FrameRecordPayloads(payloads [][]byte) []byte {
	return wirecontract.FrameRecordPayloads(payloads)
}

// UnframeRecordPayloads calls wirecontract.UnframeRecordPayloads — see
// FrameRecordPayloads' doc. Used by Service.DecodeSegment (see
// tlogservice.go).
func UnframeRecordPayloads(data []byte, maxRecords, maxBytes int) ([][]byte, error) {
	return wirecontract.UnframeRecordPayloads(data, maxRecords, maxBytes)
}
