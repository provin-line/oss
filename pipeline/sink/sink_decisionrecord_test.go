package sink_test

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/decisionrecord"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/vc"
)

type fakeRecorder struct {
	records []decisionrecord.Record
	// failAt is the 1-based call that fails; 0 means none fails.
	failAt int
	// failAll makes every call fail.
	failAll bool
	calls   int
	writes  *fakeWriter
	// writesAtRecord is the number of writer calls seen at each Record call.
	writesAtRecord []int
}

func (f *fakeRecorder) Record(_ context.Context, r decisionrecord.Record) error {
	f.calls++
	if f.writes != nil {
		f.writesAtRecord = append(f.writesAtRecord, len(f.writes.records))
	}
	if f.failAll || f.calls == f.failAt {
		return errors.New("recorder down")
	}
	f.records = append(f.records, r)
	return nil
}

const (
	testBoundary = "provin-agent-delivery@1"
	testProfile  = "purpose-first-agent-access@1"
)

var decisionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var recordClock = time.Date(2026, 11, 7, 9, 30, 0, 0, time.FixedZone("JST", 9*3600))

// agentConfig is a production purpose-first config recording to rec.
func agentConfig(a *fakeAppraiser, s *fakeStore, w *fakeWriter, rec decisionrecord.Recorder) sink.Config {
	cfg := baseConfig(&fakeVerifier{result: verified()}, s, w)
	cfg.Kind = contract.SinkProduction
	cfg.Verifier = nil
	cfg.Appraiser = a
	cfg.AgentBoundaryID = testBoundary
	cfg.DecisionRecorder = rec
	cfg.Now = func() time.Time { return recordClock }
	return cfg
}

func process(t *testing.T, cfg sink.Config, wire []byte) *contract.Result {
	t.Helper()
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Process(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestNew_AppraiserRequiresDecisionRecorder(t *testing.T) {
	payload := []byte(`{"a":1}`)
	cred := boundCred(t, payload)
	a := &fakeAppraiser{view: appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept), result: verified()}
	cfg := agentConfig(a, &fakeStore{}, &fakeWriter{}, nil)
	if _, err := sink.New(cfg); !errors.Is(err, sink.ErrMissingDecisionRecorder) {
		t.Fatalf("nil recorder with Appraiser: got %v, want ErrMissingDecisionRecorder", err)
	}
}

func TestProcess_DecisionRecord_Accepted(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	w := &fakeWriter{}
	rec := &fakeRecorder{writes: w}
	res := process(t, agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, w, rec), encode(t, cred, payload))
	if res.Status != contract.StatusPassed {
		t.Fatalf("result=%+v", res)
	}
	if len(rec.records) != 1 {
		t.Fatalf("records=%d, want 1", len(rec.records))
	}
	r := rec.records[0]
	if !decisionIDPattern.MatchString(r.DecisionID) {
		t.Errorf("DecisionID=%q, want 128 random bits as hex", r.DecisionID)
	}
	if r.Point != testBoundary || r.Outcome != decisionrecord.Accepted || r.Check != "" {
		t.Errorf("record=%+v", r)
	}
	if !r.At.Equal(recordClock) || r.At.Location() != time.UTC {
		t.Errorf("At=%v (%v), want %v in UTC", r.At, r.At.Location(), recordClock)
	}
	if len(r.Evidence) != 1 || r.Evidence[0].Role != "evidenceView" || r.Evidence[0].Address.String() != view.EvidenceViewID {
		t.Errorf("Evidence=%+v, want the evidence view %s", r.Evidence, view.EvidenceViewID)
	}
	if r.Attributes["appraisalDecision"] != "ACCEPT" || r.Attributes["decisionProfile"] != testProfile || len(r.Attributes) != 2 {
		t.Errorf("Attributes=%v", r.Attributes)
	}
	if rec.writesAtRecord[0] != 0 {
		t.Errorf("the accepted record must be written before the delivery write")
	}
}

func TestProcess_DecisionRecord_FreshIDPerDecision(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	rec := &fakeRecorder{}
	p, err := sink.New(agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, &fakeWriter{}, rec))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := p.Process(context.Background(), encode(t, cred, payload)); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.records) != 2 || rec.records[0].DecisionID == rec.records[1].DecisionID {
		t.Fatalf("records=%+v, want two with distinct DecisionIDs", rec.records)
	}
}

func TestProcess_DecisionRecord_NonAcceptAppraisalIsRefused(t *testing.T) {
	payload := []byte(`{"agent":"held"}`)
	cred := boundCred(t, payload)
	missing := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	missing.PolicyDecision = nil
	cases := []struct {
		name     string
		view     *appraisal.View
		decision string
	}{
		{"quarantine", appraisedView(t, cred, appraisal.TruthIndeterminate, appraisal.DecisionQuarantine), "QUARANTINE"},
		{"deny", appraisedView(t, cred, appraisal.TruthFailed, appraisal.DecisionDeny), "DENY"},
		{"missing", missing, "missing"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			w := &fakeWriter{}
			rec := &fakeRecorder{}
			res := process(t, agentConfig(&fakeAppraiser{view: tt.view, result: &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}}, &fakeStore{}, w, rec), encode(t, cred, payload))
			if res.Status != contract.StatusErrored || len(w.records) != 0 {
				t.Fatalf("result=%+v writes=%d", res, len(w.records))
			}
			if len(rec.records) != 1 {
				t.Fatalf("records=%d, want 1", len(rec.records))
			}
			r := rec.records[0]
			if r.Outcome != decisionrecord.Refused || r.Check != "appraisal" || r.Reason != res.Error {
				t.Errorf("record=%+v, result error=%q", r, res.Error)
			}
			if r.Attributes["appraisalDecision"] != tt.decision {
				t.Errorf("Attributes=%v, want decision %q", r.Attributes, tt.decision)
			}
			if len(r.Evidence) != 1 || r.Evidence[0].Role != "evidenceView" || r.Evidence[0].Address.String() != tt.view.EvidenceViewID {
				t.Errorf("Evidence=%+v", r.Evidence)
			}
		})
	}
}

func TestProcess_DecisionRecord_AppraiserErrorIsRefusedWithoutEvidence(t *testing.T) {
	payload := []byte(`{"agent":"x"}`)
	cred := boundCred(t, payload)
	rec := &fakeRecorder{}
	res := process(t, agentConfig(&fakeAppraiser{err: errors.New("resolver unavailable")}, &fakeStore{}, &fakeWriter{}, rec), encode(t, cred, payload))
	if res.Status != contract.StatusErrored {
		t.Fatalf("result=%+v", res)
	}
	if len(rec.records) != 1 || rec.records[0].Outcome != decisionrecord.Refused || rec.records[0].Check != "appraisal" || len(rec.records[0].Evidence) != 0 {
		t.Fatalf("records=%+v", rec.records)
	}
}

func TestProcess_DecisionRecord_LaterStageRecordsAgain(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	noHash, err := vc.New(vc.CredentialFields{
		Issuer: "did:example:upstream", ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{PipelineID: "p", ProcessID: "upstream", TransformationClaim: vc.ClaimConvert},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		wantOutcome decisionrecord.Outcome
		wantCheck   string
		wantPayload bool
		wantWrites  int
		setup       func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte
	}{
		{"verdict", decisionrecord.Refused, "verdict", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			a.result = &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}
			return encode(t, boundCred(t, payload), payload)
		}},
		{"allow-list", decisionrecord.Refused, "allow-list", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			cfg.AllowIssuers = []string{"did:example:other"}
			return encode(t, boundCred(t, payload), payload)
		}},
		{"ingress-store-failure", decisionrecord.Refused, "ingress-store-failure", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			s.returnErr = errors.New("disk full")
			return encode(t, boundCred(t, payload), payload)
		}},
		{"malformed-credential", decisionrecord.Refused, "malformed-credential", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			return encode(t, noHash, payload)
		}},
		{"binding-gate", decisionrecord.Refused, "binding-gate", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			return encode(t, boundCred(t, payload), []byte(`{"agent":"tampered"}`))
		}},
		{"payload-delivery-violation", decisionrecord.Refused, "payload-delivery-violation", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			return encode(t, boundCred(t, payload), nil)
		}},
		{"payload-fetch", decisionrecord.Refused, "payload-fetch", false, 0, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			cfg.PayloadDelivery = contract.DeliveryByReference
			cfg.PayloadResolver = &fakePayloadResolver{err: errors.New("registry down")}
			return encode(t, boundCred(t, payload), nil)
		}},
		{"write error is never a refusal", decisionrecord.Accepted, "", true, 1, func(t *testing.T, cfg *sink.Config, a *fakeAppraiser, s *fakeStore, w *fakeWriter) []byte {
			w.returnErr = errors.New("downstream unavailable")
			return encode(t, boundCred(t, payload), payload)
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cred := boundCred(t, payload)
			view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
			a := &fakeAppraiser{view: view, result: verified()}
			s, w, rec := &fakeStore{}, &fakeWriter{}, &fakeRecorder{}
			cfg := agentConfig(a, s, w, rec)
			wire := tt.setup(t, &cfg, a, s, w)
			res := process(t, cfg, wire)
			if res.Status != contract.StatusErrored {
				t.Fatalf("result=%+v", res)
			}
			if len(w.records) != tt.wantWrites {
				t.Fatalf("writer calls=%d, want %d", len(w.records), tt.wantWrites)
			}
			if len(rec.records) != 2 {
				t.Fatalf("records=%d, want 2: %+v", len(rec.records), rec.records)
			}
			first, second := rec.records[0], rec.records[1]
			if first.Outcome != decisionrecord.Accepted || first.Check != "" {
				t.Errorf("first=%+v", first)
			}
			if second.DecisionID != first.DecisionID || second.Point != testBoundary {
				t.Errorf("second=%+v does not continue %q", second, first.DecisionID)
			}
			if second.Outcome != tt.wantOutcome || second.Check != tt.wantCheck || second.Reason == "" {
				t.Errorf("second=%+v, want %s/%q with a reason", second, tt.wantOutcome, tt.wantCheck)
			}
			if tt.wantOutcome == decisionrecord.Accepted && !strings.HasPrefix(second.Reason, "write outcome unknown: ") {
				t.Errorf("Reason=%q", second.Reason)
			}
			if !second.At.Equal(recordClock) || second.At.Location() != time.UTC {
				t.Errorf("second.At=%v", second.At)
			}
			hasPayload := false
			for _, e := range second.Evidence {
				if e.Role == "payload" {
					hasPayload = e.Address.String() == rawHash(payload)
				}
			}
			if hasPayload != tt.wantPayload {
				t.Errorf("payload evidence present=%v, want %v: %+v", hasPayload, tt.wantPayload, second.Evidence)
			}
			if second.Evidence[0].Role != "evidenceView" || second.Evidence[0].Address.String() != view.EvidenceViewID {
				t.Errorf("second.Evidence=%+v", second.Evidence)
			}
			if second.Attributes["appraisalDecision"] != "ACCEPT" || second.Attributes["decisionProfile"] != view.PolicyDecision.DecisionProfileID {
				t.Errorf("second.Attributes=%v", second.Attributes)
			}
		})
	}
}

func TestProcess_DecisionRecord_UndecodableEnvelopeIsRefused(t *testing.T) {
	rec := &fakeRecorder{}
	cfg := agentConfig(&fakeAppraiser{}, &fakeStore{}, &fakeWriter{}, rec)
	res := process(t, cfg, []byte("not-an-envelope"))
	if res.Status != contract.StatusErrored || len(rec.records) != 1 {
		t.Fatalf("result=%+v records=%+v", res, rec.records)
	}
	r := rec.records[0]
	if r.Outcome != decisionrecord.Refused || r.Check != "decode" || r.Point != testBoundary || len(r.Evidence) != 0 || !decisionIDPattern.MatchString(r.DecisionID) || r.Reason != res.Error {
		t.Fatalf("record=%+v", r)
	}
	legacy := &fakeRecorder{}
	lc := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{})
	lc.DecisionRecorder = legacy
	process(t, lc, []byte("not-an-envelope"))
	if legacy.calls != 0 {
		t.Errorf("legacy path recorded an undecodable envelope")
	}
}

// Every record after the accepted one is written on a context detached from
// the processing one, with a deadline of its own.
func TestProcess_DecisionRecord_AfterAcceptRecordsUseADetachedContext(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	rec := &deadlineRecorder{}
	cfg := agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{returnErr: errors.New("disk full")}, &fakeWriter{}, rec)
	process(t, cfg, encode(t, cred, payload))
	if len(rec.hasDeadline) != 2 || rec.hasDeadline[0] || !rec.hasDeadline[1] {
		t.Fatalf("deadlines per record = %v, want [false true]", rec.hasDeadline)
	}
}

type deadlineRecorder struct{ hasDeadline []bool }

func (d *deadlineRecorder) Record(ctx context.Context, _ decisionrecord.Record) error {
	_, ok := ctx.Deadline()
	d.hasDeadline = append(d.hasDeadline, ok)
	return nil
}

// The sink's records pass a real Filter at level all over JSON lines, so a
// drift in the content-address or field formats refuses every delivery here.
func TestProcess_DecisionRecord_RealFilterAcceptsSinkRecords(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cases := []struct {
		name      string
		wantLines int
		setup     func(a *fakeAppraiser, w *fakeWriter) []byte
	}{
		{"accepted", 1, func(a *fakeAppraiser, w *fakeWriter) []byte { return encode(t, boundCred(t, payload), payload) }},
		{"write error", 2, func(a *fakeAppraiser, w *fakeWriter) []byte {
			w.returnErr = errors.New("down")
			return encode(t, boundCred(t, payload), payload)
		}},
		{"binding refused", 2, func(a *fakeAppraiser, w *fakeWriter) []byte {
			return encode(t, boundCred(t, payload), []byte(`{"agent":"other"}`))
		}},
		{"deny", 1, func(a *fakeAppraiser, w *fakeWriter) []byte {
			a.view = appraisedView(t, boundCred(t, payload), appraisal.TruthFailed, appraisal.DecisionDeny)
			a.result = &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}
			return encode(t, boundCred(t, payload), payload)
		}},
		{"appraiser error", 1, func(a *fakeAppraiser, w *fakeWriter) []byte {
			a.view, a.result, a.err = nil, nil, errors.New("boom")
			return encode(t, boundCred(t, payload), payload)
		}},
		{"decode", 1, func(a *fakeAppraiser, w *fakeWriter) []byte { return []byte("garbage") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f, err := decisionrecord.NewFilter(decisionrecord.LevelAll, decisionrecord.NewJSONLines(&buf), nil)
			if err != nil {
				t.Fatal(err)
			}
			cred := boundCred(t, payload)
			a := &fakeAppraiser{view: appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept), result: verified()}
			w := &fakeWriter{}
			cfg := agentConfig(a, &fakeStore{}, w, f)
			wire := tt.setup(a, w)
			res := process(t, cfg, wire)
			if strings.Contains(res.Error, "decision record") {
				t.Fatalf("the Filter refused a record: %s", res.Error)
			}
			if n := strings.Count(buf.String(), "\n"); n != tt.wantLines {
				t.Fatalf("lines=%d, want %d: %s", n, tt.wantLines, buf.String())
			}
		})
	}
}

func TestProcess_DecisionRecord_ReceiptFailureIsNotARefusal(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	rec := &fakeRecorder{}
	cfg := agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, &fakeWriter{}, rec)
	cfg.Receipts = &fakeReceiptIssuer{err: errors.New("receipt store down")}
	res := process(t, cfg, encode(t, cred, payload))
	if res.Status != contract.StatusErrored {
		t.Fatalf("result=%+v", res)
	}
	if len(rec.records) != 1 || rec.records[0].Outcome != decisionrecord.Accepted {
		t.Fatalf("records=%+v: the payload was delivered, so the decision stays accepted", rec.records)
	}
}

func TestProcess_DecisionRecord_FailureRefusesTheDelivery(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	s, w := &fakeStore{}, &fakeWriter{}
	rl := &fakeRejectLog{}
	rec := &fakeRecorder{failAll: true}
	cfg := agentConfig(&fakeAppraiser{view: view, result: verified()}, s, w, rec)
	cfg.RejectLog = rl
	res := process(t, cfg, encode(t, cred, payload))
	if res.Status != contract.StatusErrored || res.Error == "" {
		t.Fatalf("result=%+v", res)
	}
	if len(w.records) != 0 || s.calls != 0 {
		t.Fatalf("writes=%d stores=%d, want none after a failed record", len(w.records), s.calls)
	}
	if len(rl.records) != 1 || rl.records[0].Reason != sink.RejectDecisionRecord {
		t.Fatalf("reject log=%+v, want one decision-record reject", rl.records)
	}
}

func TestProcess_DecisionRecord_RefusalRecordFailureKeepsTheRefusal(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	w := &fakeWriter{returnErr: errors.New("downstream unavailable")}
	rec := &fakeRecorder{failAt: 2}
	res := process(t, agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, w, rec), encode(t, cred, payload))
	if res.Status != contract.StatusErrored || rec.calls != 2 {
		t.Fatalf("result=%+v calls=%d", res, rec.calls)
	}
}

func TestProcess_DecisionRecord_LegacyPathRecordsNothing(t *testing.T) {
	payload := []byte(`{"x":1}`)
	cred := boundCred(t, payload)
	rec := &fakeRecorder{}
	cfg := baseConfig(&fakeVerifier{result: verified()}, &fakeStore{}, &fakeWriter{})
	cfg.Kind = contract.SinkProduction
	cfg.DecisionRecorder = rec
	res := process(t, cfg, encode(t, cred, payload))
	if res.Status != contract.StatusPassed || rec.calls != 0 {
		t.Fatalf("result=%+v record calls=%d", res, rec.calls)
	}
}

type discardRecorder struct{}

func (discardRecorder) Record(context.Context, decisionrecord.Record) error { return nil }

// ctxRecorder fails the test if it is handed a done context: a refusal after
// cancellation must be written on a detached context.
type ctxRecorder struct {
	t       *testing.T
	records []decisionrecord.Record
}

func (c *ctxRecorder) Record(ctx context.Context, r decisionrecord.Record) error {
	if ctx.Err() != nil {
		c.t.Errorf("record %+v written on a done context: %v", r, ctx.Err())
		return ctx.Err()
	}
	c.records = append(c.records, r)
	return nil
}

type cancellingStore struct{ cancel context.CancelFunc }

func (c cancellingStore) StoreIngressVC(context.Context, *vc.PipelinePassCredential, string) error {
	c.cancel()
	return context.Canceled
}

type cancellingWriter struct{ cancel context.CancelFunc }

func (c cancellingWriter) Write(context.Context, sink.Record) error {
	c.cancel()
	return context.Canceled
}

type cancellingResolver struct{ cancel context.CancelFunc }

func (c cancellingResolver) ResolvePayload(context.Context, string, string) ([]byte, error) {
	c.cancel()
	return nil, errors.New("fetch interrupted")
}

func TestProcess_DecisionRecord_CancellationAfterAcceptanceRecordsRefusal(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cases := []struct {
		name       string
		wantCheck  string
		wantUnsure bool
		setup      func(cfg *sink.Config, cancel context.CancelFunc) []byte
	}{
		{"store", "cancelled", false, func(cfg *sink.Config, cancel context.CancelFunc) []byte {
			cfg.Store = cancellingStore{cancel}
			return encode(t, boundCred(t, payload), payload)
		}},
		{"payload", "cancelled", false, func(cfg *sink.Config, cancel context.CancelFunc) []byte {
			cfg.PayloadDelivery = contract.DeliveryByReference
			cfg.PayloadResolver = cancellingResolver{cancel}
			return encode(t, boundCred(t, payload), nil)
		}},
		{"write", "", true, func(cfg *sink.Config, cancel context.CancelFunc) []byte {
			cfg.Writer = cancellingWriter{cancel}
			return encode(t, boundCred(t, payload), payload)
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cred := boundCred(t, payload)
			view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
			rec := &ctxRecorder{t: t}
			cfg := agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, &fakeWriter{}, rec)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wire := tt.setup(&cfg, cancel)
			p, err := sink.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			res, err := p.Process(ctx, wire)
			if res != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("res=%+v err=%v, want the context error", res, err)
			}
			if len(rec.records) != 2 {
				t.Fatalf("records=%+v, want accepted then refused", rec.records)
			}
			first, second := rec.records[0], rec.records[1]
			wantOutcome := decisionrecord.Refused
			if tt.wantUnsure {
				wantOutcome = decisionrecord.Accepted
			}
			if second.DecisionID != first.DecisionID || second.Outcome != wantOutcome || second.Check != tt.wantCheck || second.Reason == "" {
				t.Errorf("second=%+v, want %s/%q on %q", second, wantOutcome, tt.wantCheck, first.DecisionID)
			}
			if tt.wantUnsure && !strings.Contains(second.Reason, "unknown") {
				t.Errorf("Reason=%q, want it to say the write's outcome is unknown", second.Reason)
			}
		})
	}
}

func TestProcess_DecisionRecord_CancellationRecordFailureStillReturnsContextError(t *testing.T) {
	payload := []byte(`{"agent":"safe"}`)
	cred := boundCred(t, payload)
	view := appraisedView(t, cred, appraisal.TruthVerified, appraisal.DecisionAccept)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &fakeRecorder{failAt: 2}
	cfg := agentConfig(&fakeAppraiser{view: view, result: verified()}, &fakeStore{}, &fakeWriter{}, rec)
	cfg.Writer = cancellingWriter{cancel}
	p, err := sink.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(ctx, encode(t, cred, payload)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want the context error", err)
	}
}
