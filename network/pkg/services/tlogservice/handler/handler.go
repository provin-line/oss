// Package handler is the proto↔domain boundary for TlogService: it converts
// wire messages to and from the tlogservice domain and maps sentinel errors
// to Connect codes (errors.Is, never string matching). It holds no domain
// logic (AGENTS.md: handler = proto↔domain + error mapping only).
package handler

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"

	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/network/pkg/pagination"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/tlog"
)

// Service is the consumer-side view of the tlog read service the handler
// depends on (defined here to keep the dependency pointing inward).
// *tlogservice.Service satisfies it.
type Service interface {
	Checkpoint(ctx context.Context, logID string) (*tlog.Checkpoint, error)
	Records(ctx context.Context, logID string, start uint64, count int) ([]*tlog.Record, error)
}

// Handler adapts a Service to the generated TlogServiceHandler. It embeds
// the Unimplemented stub so MirrorLogSegment / GetMirrorState (D-T2's
// mirror-custody surface) report CodeUnimplemented until the registry-side
// mirror store and identity predicate land (mirrors OperatorHandler's use
// of chainpbconnect.UnimplementedChainServiceHandler for the same reason:
// proto surface staged ahead of its domain wiring).
type Handler struct {
	tlogpbconnect.UnimplementedTlogServiceHandler
	svc Service
}

var _ tlogpbconnect.TlogServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GetLogCheckpoint(ctx context.Context, req *connect.Request[tlogpb.GetLogCheckpointRequest]) (*connect.Response[tlogpb.GetLogCheckpointResponse], error) {
	cp, err := h.svc.Checkpoint(ctx, req.Msg.GetLogId())
	if err != nil {
		return nil, mapError(err)
	}
	// log_id is projected from the SIGNED checkpoint (cp.Origin), never
	// echoed from the request: the response value must be the one inside
	// the signature (the service already rejects an origin mismatch).
	return connect.NewResponse(&tlogpb.GetLogCheckpointResponse{
		LogId:     cp.Origin,
		Size:      strconv.FormatUint(cp.Size, 10),
		Head:      cp.Head,
		Timestamp: cp.Timestamp.UTC().Format(time.RFC3339),
		SignedBy:  cp.SignedBy,
		Signature: cp.Signature,
	}), nil
}

func (h *Handler) ListLogRecords(ctx context.Context, req *connect.Request[tlogpb.ListLogRecordsRequest]) (*connect.Response[tlogpb.ListLogRecordsResponse], error) {
	count, err := pagination.ClampSize(req.Msg.GetCount())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	start := uint64(0)
	if raw := req.Msg.GetStartIndex(); raw != "" {
		start, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("start_index %q is not a decimal uint64: %w", raw, err))
		}
	}
	records, err := h.svc.Records(ctx, req.Msg.GetLogId(), start, count)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &tlogpb.ListLogRecordsResponse{}
	for _, rec := range records {
		resp.Records = append(resp.Records, &tlogpb.LogRecord{
			Index:   strconv.FormatUint(rec.Index, 10),
			Payload: rec.Payload,
			Hash:    rec.Hash,
		})
	}
	return connect.NewResponse(resp), nil
}

// mapError translates domain sentinel errors to Connect codes. Unrecognized
// errors — including an unsigned log asked for a checkpoint, which is a
// node misconfiguration, never absence — become CodeInternal.
func mapError(err error) error {
	switch {
	case errors.Is(err, tlogservice.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, tlogservice.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
