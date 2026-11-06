package sink

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

type captureRecorder struct{ records []decisionrecord.Record }

func (c *captureRecorder) Record(_ context.Context, r decisionrecord.Record) error {
	c.records = append(c.records, r)
	return nil
}

// After a decision was accepted, a rejection for any reason records a refusal
// whose Check is the reason, and the record is valid for a real Filter.
func TestReject_AfterAcceptanceRecordsEveryReason(t *testing.T) {
	reasons := []RejectReason{
		RejectDecodeFailure, RejectMalformedCredential, RejectVerdict, RejectAllowList,
		RejectBindingGate, RejectByReferenceUnsupported, RejectPayloadFetch,
		RejectPayloadDeliveryViolation, RejectIngressStoreFailure, RejectAppraisal,
		RejectDecisionRecord, RejectReason("a-reason-added-later"),
	}
	for _, reason := range reasons {
		t.Run(string(reason), func(t *testing.T) {
			rec := &captureRecorder{}
			f, err := decisionrecord.NewFilter(decisionrecord.LevelAll, rec2sink{rec}, nil)
			if err != nil {
				t.Fatal(err)
			}
			p := &Processor{cfg: Config{DecisionRecorder: f, AgentBoundaryID: "provin-agent-delivery@1"}, logger: nopLogger(), now: fixedNow}
			dec := &decision{id: "0123456789abcdef0123456789abcdef", view: "sha256:" + hex64, profile: "p@1", outcome: "ACCEPT"}
			p.reject(context.Background(), dec, reason, "refused", nil, "", "", "")
			if len(rec.records) != 1 || rec.records[0].Outcome != decisionrecord.Refused || rec.records[0].Check != string(reason) || rec.records[0].DecisionID != dec.id {
				t.Fatalf("records=%+v", rec.records)
			}
			rec2 := &captureRecorder{}
			p.cfg.DecisionRecorder = rec2
			p.reject(context.Background(), nil, reason, "refused", nil, "", "", "")
			if len(rec2.records) != 0 {
				t.Fatalf("a rejection without an accepted decision recorded %+v", rec2.records)
			}
		})
	}
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type rec2sink struct{ c *captureRecorder }

func (r rec2sink) Record(ctx context.Context, rc decisionrecord.Record) error {
	return r.c.Record(ctx, rc)
}
func (rec2sink) Summary(context.Context, decisionrecord.Summary) error { return nil }

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func fixedNow() time.Time { return time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC) }
