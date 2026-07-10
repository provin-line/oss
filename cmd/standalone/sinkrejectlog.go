package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/tlog"
)

// sinkRejectLog is the composition-root sink.RejectLog: it serializes each reject
// record to JSON and appends it to a durable, hash-chained log, giving an archival
// sink its reject-with-audit-log obligation. The record type carries no payload,
// so a rejected event's bytes are never hoarded in the evidence store.
type sinkRejectLog struct {
	log tlog.Log
}

var _ sink.RejectLog = (*sinkRejectLog)(nil)

// RecordReject appends the reject record as one durable, hash-chained entry.
func (r *sinkRejectLog) RecordReject(ctx context.Context, rec sink.RejectRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("sinkRejectLog: marshal reject record: %w", err)
	}
	if _, err := r.log.Append(ctx, b); err != nil {
		return fmt.Errorf("sinkRejectLog: append reject record: %w", err)
	}
	return nil
}
