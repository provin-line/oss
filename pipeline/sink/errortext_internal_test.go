package sink

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

// A decision record's Reason is within pipeexcerpt.TextLimit bytes of UTF-8,
// however long the reason given: a refusal after acceptance and one before any
// decision.
func TestRecord_ReasonWithinTheLimit(t *testing.T) {
	long := strings.Repeat("ab\n\xff", 64<<10)
	rec := &captureRecorder{}
	p := &Processor{cfg: Config{DecisionRecorder: rec, AgentBoundaryID: "provin-agent-delivery@1"}, logger: nopLogger(), now: fixedNow}
	view, err := contentaddress.Parse("sha256:" + hex64)
	if err != nil {
		t.Fatal(err)
	}
	dec := &decision{id: "0123456789abcdef0123456789abcdef", view: view, profile: "p@1", outcome: "ACCEPT"}
	p.reject(context.Background(), dec, RejectVerdict, long, nil, "", "", "")
	p.recordUndecided(context.Background(), "decode", nil, "", long)
	if len(rec.records) != 2 {
		t.Fatalf("%d records, want 2", len(rec.records))
	}
	for _, r := range rec.records {
		if len(r.Reason) > pipeexcerpt.TextLimit || !utf8.ValidString(r.Reason) {
			t.Errorf("%s record: Reason of %d bytes", r.Check, len(r.Reason))
		}
	}
}

type captureRejectLog struct{ records []RejectRecord }

func (c *captureRejectLog) RecordReject(_ context.Context, r RejectRecord) error {
	c.records = append(c.records, r)
	return nil
}

// Whatever the reason, a reject records its Detail and IssuerDID within
// pipeexcerpt.TextLimit bytes of UTF-8, holding no refused bytes whole, and
// returns a Result whose Error is within the same limit.
func TestReject_EveryReasonRecordsWithinTheLimit(t *testing.T) {
	refused := strings.Repeat("refused-", 64<<10)
	reasons := []RejectReason{
		RejectDecodeFailure, RejectMalformedCredential, RejectVerdict, RejectAllowList,
		RejectBindingGate, RejectByReferenceUnsupported, RejectPayloadFetch,
		RejectPayloadDeliveryViolation, RejectIngressStoreFailure, RejectAppraisal,
		RejectDecisionRecord,
	}
	for _, reason := range reasons {
		rl := &captureRejectLog{}
		p := &Processor{cfg: Config{RejectLog: rl}, logger: nopLogger(), now: fixedNow}
		r := p.reject(context.Background(), nil, reason, "refused: "+refused, nil, "", "", "did:example:"+refused)
		if len(rl.records) != 1 {
			t.Fatalf("%s: %d records", reason, len(rl.records))
		}
		rec := rl.records[0]
		for _, f := range []struct{ name, s string }{{"Detail", rec.Detail}, {"IssuerDID", rec.IssuerDID}, {"Result.Error", r.Error}} {
			if len(f.s) > pipeexcerpt.TextLimit || !utf8.ValidString(f.s) || strings.Contains(f.s, refused) {
				t.Errorf("%s: %s of %d bytes", reason, f.name, len(f.s))
			}
		}
	}
}
