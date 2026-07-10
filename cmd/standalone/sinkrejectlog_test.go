package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/tlog"
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
