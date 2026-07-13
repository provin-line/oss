package tlogservice_test

import (
	"context"
	"errors"
	"testing"

	policy "github.com/o3co/protobuf.interceptors/schema"
	"google.golang.org/protobuf/proto"

	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/memlog"
)

const logID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pipe"

func seeded(t *testing.T, n int) *tlogservice.Service {
	t.Helper()
	l := memlog.New()
	for i := 0; i < n; i++ {
		if _, err := l.Append(context.Background(), []byte{byte('a' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	return tlogservice.New(map[string]tlog.Log{logID: l})
}

func TestRecords_RangeSemantics(t *testing.T) {
	ctx := context.Background()
	svc := seeded(t, 3)

	full, err := svc.Records(ctx, logID, 0, 10)
	if err != nil || len(full) != 3 || full[0].Index != 0 || full[2].Index != 2 {
		t.Fatalf("full range = %+v (err %v), want indexes 0..2", full, err)
	}
	mid, err := svc.Records(ctx, logID, 1, 1)
	if err != nil || len(mid) != 1 || mid[0].Index != 1 || string(mid[0].Payload) != "b" {
		t.Fatalf("mid range = %+v (err %v), want [record 1]", mid, err)
	}
	// A caught-up reader is a normal state, not an error.
	if past, err := svc.Records(ctx, logID, 3, 5); err != nil || len(past) != 0 {
		t.Fatalf("past-the-end = %+v (err %v), want empty", past, err)
	}
	if _, err := svc.Records(ctx, logID, 0, 0); !errors.Is(err, tlogservice.ErrInvalidArgument) {
		t.Fatalf("count 0: err=%v, want ErrInvalidArgument", err)
	}
	if _, err := svc.Records(ctx, "did:dplaax:reg:org:x:pipeline:none", 0, 5); !errors.Is(err, tlogservice.ErrNotFound) {
		t.Fatalf("unknown log: err=%v, want ErrNotFound", err)
	}
}

func TestCheckpoint_UnknownLogAndUnsigned(t *testing.T) {
	ctx := context.Background()
	svc := seeded(t, 1)
	if _, err := svc.Checkpoint(ctx, "did:dplaax:reg:org:x:pipeline:none"); !errors.Is(err, tlogservice.ErrNotFound) {
		t.Fatalf("unknown log: err=%v, want ErrNotFound", err)
	}
	// memlog cannot sign: the error surfaces (misconfiguration), never absence.
	if _, err := svc.Checkpoint(ctx, logID); err == nil || errors.Is(err, tlogservice.ErrNotFound) {
		t.Fatalf("unsigned log checkpoint: err=%v, want a non-notfound error", err)
	}
}

// Fail-open guard: every TlogService RPC must carry the o3co.authz.v1.policy
// option with the frozen tlog/read pair (mirrors the audit/vc descriptor
// tests).
func TestTlogService_RPCPolicies(t *testing.T) {
	want := map[string]struct{ resource, action string }{
		"GetLogCheckpoint": {"tlog", "read"},
		"ListLogRecords":   {"tlog", "read"},
	}
	methods := tlogpb.File_dplaax_tlog_v1_tlog_proto.Services().ByName("TlogService").Methods()
	if methods.Len() != len(want) {
		t.Fatalf("TlogService has %d methods, want %d", methods.Len(), len(want))
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		if !proto.HasExtension(m.Options(), policy.E_Policy) {
			t.Errorf("RPC %s is missing the o3co.authz.v1.policy option", name)
			continue
		}
		w, ok := want[name]
		if !ok {
			t.Errorf("unexpected RPC %s", name)
			continue
		}
		p, ok := proto.GetExtension(m.Options(), policy.E_Policy).(*policy.Policy)
		if !ok || p == nil || p.GetResource() != w.resource || p.GetAction() != w.action {
			t.Errorf("RPC %s: policy = %+v, want {%s %s}", name, p, w.resource, w.action)
		}
	}
}

// originLog is a stub whose Checkpoint returns a controlled Origin — driving
// the P0-1 fail-closed guard: the signed origin must match the registry key.
type originLog struct {
	tlog.Log
	origin string
}

func (o originLog) Checkpoint(context.Context) (*tlog.Checkpoint, error) {
	return &tlog.Checkpoint{Origin: o.origin, Size: 1, Head: "h", SignedBy: "did:x#s"}, nil
}

func TestCheckpointOriginGuard(t *testing.T) {
	svc := tlogservice.New(map[string]tlog.Log{
		"good": originLog{origin: "good"},
		"bad":  originLog{origin: "not-the-key"},
	})
	if cp, err := svc.Checkpoint(context.Background(), "good"); err != nil || cp.Origin != "good" {
		t.Fatalf("matching origin: cp=%v err=%v", cp, err)
	}
	if _, err := svc.Checkpoint(context.Background(), "bad"); err == nil {
		t.Fatal("mismatched signed origin vs registry key: want fail-closed error")
	}
}
