package handler_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/handler"
	"github.com/provin-line/oss/tlog"
)

type fakeService struct {
	cp   *tlog.Checkpoint
	recs []*tlog.Record
	err  error

	gotStart uint64
	gotCount int

	capErr error
}

func (f *fakeService) Checkpoint(context.Context, string) (*tlog.Checkpoint, error) {
	return f.cp, f.err
}

func (f *fakeService) Records(_ context.Context, _ string, start uint64, count int) ([]*tlog.Record, error) {
	f.gotStart, f.gotCount = start, count
	return f.recs, f.err
}

func (f *fakeService) MirrorState(string) (uint64, error) { return 0, f.err }

func (f *fakeService) MirrorSegment(context.Context, tlogservice.MirrorSegmentInput) (uint64, error) {
	return 0, f.err
}

// CheckBatchCaps lets a fakeService drive the handler's pre-auth cap guard;
// the zero value (nil) keeps the not-configured tests reaching MirrorSegment's
// ErrMirrorNotConfigured unchanged.
func (f *fakeService) CheckBatchCaps(int, int) error {
	return f.capErr
}

func TestGetLogCheckpoint_Projection(t *testing.T) {
	ts := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	// The response log_id is projected from the SIGNED checkpoint (Origin),
	// never echoed from the request (P0-1) — the fixture origin is what must
	// come back.
	h := handler.New(&fakeService{cp: &tlog.Checkpoint{
		Origin: "did:x:pipeline:p", Size: 42, Head: "headhash", Timestamp: ts, SignedBy: "did:x#signing", Signature: []byte{1, 2},
	}}, nil)
	resp, err := h.GetLogCheckpoint(context.Background(), connect.NewRequest(&tlogpb.GetLogCheckpointRequest{LogId: "did:x:pipeline:p"}))
	if err != nil {
		t.Fatalf("GetLogCheckpoint: %v", err)
	}
	m := resp.Msg
	if m.GetLogId() != "did:x:pipeline:p" || m.GetSize() != "42" || m.GetHead() != "headhash" ||
		m.GetTimestamp() != "2026-07-07T09:00:00Z" || m.GetSignedBy() != "did:x#signing" || len(m.GetSignature()) != 2 {
		t.Fatalf("projection = %+v", m)
	}
}

func TestListLogRecords_ProjectionAndRange(t *testing.T) {
	svc := &fakeService{recs: []*tlog.Record{{Index: 7, Payload: []byte("p"), Hash: "h"}}}
	h := handler.New(svc, nil)
	resp, err := h.ListLogRecords(context.Background(), connect.NewRequest(&tlogpb.ListLogRecordsRequest{
		LogId: "did:x:pipeline:p", StartIndex: "7", Count: 5,
	}))
	if err != nil {
		t.Fatalf("ListLogRecords: %v", err)
	}
	if svc.gotStart != 7 || svc.gotCount != 5 {
		t.Errorf("range passed = (%d,%d), want (7,5)", svc.gotStart, svc.gotCount)
	}
	recs := resp.Msg.GetRecords()
	if len(recs) != 1 || recs[0].GetIndex() != "7" || string(recs[0].GetPayload()) != "p" || recs[0].GetHash() != "h" {
		t.Fatalf("records = %+v", recs)
	}
	// Empty start_index means 0; count 0 means the convention default.
	if _, err := h.ListLogRecords(context.Background(), connect.NewRequest(&tlogpb.ListLogRecordsRequest{LogId: "x"})); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if svc.gotStart != 0 || svc.gotCount != 64 {
		t.Errorf("defaults passed = (%d,%d), want (0,64)", svc.gotStart, svc.gotCount)
	}
}

func TestListLogRecords_InvalidInputs(t *testing.T) {
	h := handler.New(&fakeService{}, nil)
	for _, req := range []*tlogpb.ListLogRecordsRequest{
		{LogId: "x", StartIndex: "not-a-number"},
		{LogId: "x", StartIndex: "-1"},
		{LogId: "x", Count: -1},
	} {
		if _, err := h.ListLogRecords(context.Background(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("req %+v: code = %v, want InvalidArgument", req, connect.CodeOf(err))
		}
	}
}

func TestErrorMapping(t *testing.T) {
	notFound := handler.New(&fakeService{err: fmt.Errorf("wrap: %w", tlogservice.ErrNotFound)}, nil)
	if _, err := notFound.GetLogCheckpoint(context.Background(), connect.NewRequest(&tlogpb.GetLogCheckpointRequest{LogId: "x"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("not found: code = %v", connect.CodeOf(err))
	}
	internal := handler.New(&fakeService{err: fmt.Errorf("unsigned log")}, nil)
	if _, err := internal.GetLogCheckpoint(context.Background(), connect.NewRequest(&tlogpb.GetLogCheckpointRequest{LogId: "x"})); connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("unsigned: code = %v, want Internal", connect.CodeOf(err))
	}
}
