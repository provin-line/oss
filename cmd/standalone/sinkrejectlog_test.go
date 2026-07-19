package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/memlog"
)

type capturingLog struct {
	appended [][]byte
}

func (c *capturingLog) Append(_ context.Context, payload []byte) (*tlog.Record, error) {
	c.appended = append(c.appended, append([]byte(nil), payload...))
	return &tlog.Record{Index: uint64(len(c.appended) - 1)}, nil
}
func (c *capturingLog) Get(context.Context, uint64) (*tlog.Record, error)    { return nil, nil }
func (c *capturingLog) Size(context.Context) (uint64, error)                 { return uint64(len(c.appended)), nil }
func (c *capturingLog) Checkpoint(context.Context) (*tlog.Checkpoint, error) { return nil, nil }

func TestSinkRejectLog_RecordReject(t *testing.T) {
	cap := &capturingLog{}
	rl := &sinkRejectLog{log: cap}

	rec := sink.RejectRecord{
		Reason:         sink.RejectAllowList,
		Detail:         "issuer not allow-listed",
		CredentialHash: "sha256:abc",
		IssuerDID:      "did:dplaax:reg:org:evil:pipeline:p:process:up",
	}
	if err := rl.RecordReject(context.Background(), rec); err != nil {
		t.Fatalf("RecordReject: %v", err)
	}
	if len(cap.appended) != 1 {
		t.Fatalf("appended %d records, want 1", len(cap.appended))
	}
	// The entry is JSON carrying the reason + identity, and NO payload field.
	var got map[string]any
	if err := json.Unmarshal(cap.appended[0], &got); err != nil {
		t.Fatalf("appended record is not JSON: %v", err)
	}
	if got["reason"] != "allow-list" {
		t.Errorf("reason = %v, want allow-list", got["reason"])
	}
	if _, hasPayload := got["payload"]; hasPayload {
		t.Error("reject record must not carry a payload")
	}
	if strings.Contains(strings.ToLower(string(cap.appended[0])), "payload") {
		t.Error("reject record JSON mentions payload")
	}
}

// TestSinkRejectLog_MemlogFallbackUnsigned is the unit-test seam invariant
// (RejectLogDir == ""): RecordReject still appends durably (memlog is
// hash-chained in-memory), but memlog holds no signing key, so Checkpoint
// still fails ErrUnsignedLog — the reject log's signed-identity arming
// (D-T3) only ever applies to the durable filelog path, never this seam.
func TestSinkRejectLog_MemlogFallbackUnsigned(t *testing.T) {
	rl := &sinkRejectLog{log: memlog.New()}

	rec := sink.RejectRecord{Reason: sink.RejectVerdict, Detail: "not verified"}
	if err := rl.RecordReject(context.Background(), rec); err != nil {
		t.Fatalf("RecordReject on memlog fallback: %v", err)
	}
	size, err := rl.log.Size(context.Background())
	if err != nil || size != 1 {
		t.Fatalf("memlog size = %d (err %v), want 1 (durable append)", size, err)
	}

	if _, err := rl.log.Checkpoint(context.Background()); !errors.Is(err, tlog.ErrUnsignedLog) {
		t.Fatalf("Checkpoint on memlog fallback = %v, want tlog.ErrUnsignedLog", err)
	}
}
