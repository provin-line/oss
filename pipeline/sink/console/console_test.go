package console_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/vc"
)

// compile-time: *Writer must implement sink.SinkWriter.
var _ sink.SinkWriter = (*console.Writer)(nil)

func cred(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	c, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:p",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "proc",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          "sha256:" + strings.Repeat("a", 64),
		},
	})
	if err != nil {
		t.Fatalf("cred: %v", err)
	}
	return c
}

func TestWrite_NDJSONLine(t *testing.T) {
	var buf bytes.Buffer
	w := console.New(&buf)

	payload := []byte(`{"msg":"hi"}`)
	c := cred(t)
	rec := sink.SinkRecord{Credential: c, Payload: payload, Verdict: &vc.VerifyResult{Overall: vc.ConfidenceVerified}}

	if err := w.Write(context.Background(), rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output must end with a newline (NDJSON): %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("one record must be exactly one line, got %d newlines", strings.Count(out, "\n"))
	}

	var got struct {
		Credential string          `json:"credential"`
		Confidence string          `json:"confidence"`
		Payload    json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("record is not valid JSON: %v (%q)", err, out)
	}
	wantAddr, _ := c.Hash()
	if got.Credential != wantAddr {
		t.Errorf("credential=%q, want %q", got.Credential, wantAddr)
	}
	if got.Confidence != "verified" {
		t.Errorf("confidence=%q, want %q", got.Confidence, "verified")
	}
	// Payload rides as embedded JSON, not a re-encoded string.
	if string(got.Payload) != string(payload) {
		t.Errorf("payload=%q, want %q", got.Payload, payload)
	}
}

func TestWrite_ConfidenceMapping(t *testing.T) {
	cases := map[vc.ConfidenceState]string{
		vc.ConfidenceVerified:      "verified",
		vc.ConfidenceFailed:        "failed",
		vc.ConfidenceIndeterminate: "indeterminate",
	}
	for state, want := range cases {
		var buf bytes.Buffer
		w := console.New(&buf)
		rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{}`), Verdict: &vc.VerifyResult{Overall: state}}
		if err := w.Write(context.Background(), rec); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if !strings.Contains(buf.String(), `"confidence":"`+want+`"`) {
			t.Errorf("state %v: output %q missing confidence %q", state, buf.String(), want)
		}
	}
}

// A nil verdict surfaces as "unknown" rather than panicking.
func TestWrite_NilVerdict_Unknown(t *testing.T) {
	var buf bytes.Buffer
	w := console.New(&buf)
	rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{}`), Verdict: nil}
	if err := w.Write(context.Background(), rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), `"confidence":"unknown"`) {
		t.Errorf("nil verdict should map to unknown, got %q", buf.String())
	}
}

func TestWrite_MultipleRecords_OneLineEach(t *testing.T) {
	var buf bytes.Buffer
	w := console.New(&buf)
	for i := 0; i < 3; i++ {
		rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{"i":1}`), Verdict: &vc.VerifyResult{Overall: vc.ConfidenceVerified}}
		if err := w.Write(context.Background(), rec); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Errorf("3 records → %d lines, want 3", got)
	}
}

// Underlying writer error propagates.
func TestWrite_WriterError_Propagates(t *testing.T) {
	w := console.New(errWriter{})
	rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{}`), Verdict: &vc.VerifyResult{Overall: vc.ConfidenceVerified}}
	if err := w.Write(context.Background(), rec); err == nil {
		t.Fatal("expected the underlying writer error to propagate")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

// Concurrent writes must not interleave or race (NDJSON line atomicity).
func TestWrite_ConcurrentLinesIntact(t *testing.T) {
	var buf bytes.Buffer
	w := console.New(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{"k":"v"}`), Verdict: &vc.VerifyResult{Overall: vc.ConfidenceVerified}}
			_ = w.Write(context.Background(), rec)
		}()
	}
	wg.Wait()
	// Every line must independently parse as JSON (no interleaving).
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("interleaved/garbled line: %v (%q)", err, line)
		}
	}
}

// Context cancellation is honored before writing.
func TestWrite_CtxCancelled(t *testing.T) {
	var buf bytes.Buffer
	w := console.New(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := sink.SinkRecord{Credential: cred(t), Payload: []byte(`{}`), Verdict: &vc.VerifyResult{Overall: vc.ConfidenceVerified}}
	if err := w.Write(ctx, rec); !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v, want context.Canceled", err)
	}
	if buf.Len() != 0 {
		t.Error("nothing should be written after cancellation")
	}
}
