package logobserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/observer/logobserver"
	"github.com/provin-line/oss/vc"
)

var _ contract.ProcessObserver = (*logobserver.Observer)(nil)

// record decodes the single JSON slog line a run produces.
func record(t *testing.T, ev contract.ProcessEvent) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	obs := logobserver.New(slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := obs.OnProcessComplete(context.Background(), ev); err != nil {
		t.Fatalf("OnProcessComplete returned %v, want nil (fire-and-forget)", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("log line is not one JSON record: %v\n%s", err, buf.String())
	}
	return m
}

func conf(c vc.ConfidenceState) *vc.ConfidenceState { return &c }

// A producing pass logs its issued reference, hashes, and status — and no
// empty-role fields (no consumedVCRef, no error).
func TestOnProcessComplete_ProducingPass(t *testing.T) {
	m := record(t, contract.ProcessEvent{
		Result:      &contract.Result{Status: contract.StatusPassed},
		InputHash:   "sha256:in",
		OutputHash:  "sha256:out",
		IssuedVCRef: "sha256:vc",
		Timestamp:   time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
	})
	if m["status"] != "passed" || m["inputHash"] != "sha256:in" || m["outputHash"] != "sha256:out" || m["issuedVCRef"] != "sha256:vc" {
		t.Errorf("record = %v, want passed producing fields", m)
	}
	if m["timestamp"] != "2026-07-13T09:00:00Z" {
		t.Errorf("timestamp = %v, want RFC3339 UTC", m["timestamp"])
	}
	if _, ok := m["consumedVCRef"]; ok {
		t.Error("producing event logged a consumedVCRef")
	}
	if _, ok := m["error"]; ok {
		t.Error("passed event logged an error field")
	}
	if m["msg"] != "pipeline event observed" {
		t.Errorf("msg = %v", m["msg"])
	}
}

// A terminating sink logs consumedVCRef and no issuedVCRef — the role-named
// fields the contract distinguishes.
func TestOnProcessComplete_TerminatingSink(t *testing.T) {
	m := record(t, contract.ProcessEvent{
		Result:        &contract.Result{Status: contract.StatusPassed},
		InputHash:     "sha256:in",
		ConsumedVCRef: "sha256:consumed",
		Timestamp:     time.Now(),
	})
	if m["consumedVCRef"] != "sha256:consumed" {
		t.Errorf("consumedVCRef = %v", m["consumedVCRef"])
	}
	if _, ok := m["issuedVCRef"]; ok {
		t.Error("sink event logged an issuedVCRef")
	}
}

// The core Codex-Medium case: a PASSED sink carrying a FAILED confidence must
// log confidence, so the record cannot be mistaken for a verified success.
func TestOnProcessComplete_PassedButFailedConfidence(t *testing.T) {
	m := record(t, contract.ProcessEvent{
		Result:        &contract.Result{Status: contract.StatusPassed, Confidence: conf(vc.ConfidenceFailed)},
		ConsumedVCRef: "sha256:consumed",
		Timestamp:     time.Now(),
	})
	if m["status"] != "passed" {
		t.Errorf("status = %v, want passed", m["status"])
	}
	if m["confidence"] != "failed" {
		t.Errorf("confidence = %v, want failed (a passed-but-failed record must not read as verified)", m["confidence"])
	}
}

// Confidence is omitted when no verification ran (nil), and mapped for each verdict.
func TestOnProcessComplete_Confidence(t *testing.T) {
	if m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusPassed}}); func() bool { _, ok := m["confidence"]; return ok }() {
		t.Error("nil Confidence must be omitted")
	}
	for state, want := range map[vc.ConfidenceState]string{
		vc.ConfidenceVerified:      "verified",
		vc.ConfidenceIndeterminate: "indeterminate",
		vc.ConfidenceFailed:        "failed",
	} {
		m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusPassed, Confidence: conf(state)}})
		if m["confidence"] != want {
			t.Errorf("confidence(%v) = %v, want %q", state, m["confidence"], want)
		}
	}
}

// filteredAtStep is logged for a filtered event — including index 0, which is a
// valid step, so the field keys on status rather than a non-zero value.
func TestOnProcessComplete_FilteredAtStep(t *testing.T) {
	for _, step := range []int{0, 3} {
		m := record(t, contract.ProcessEvent{
			Result: &contract.Result{Status: contract.StatusFiltered, FilteredAtStep: step},
		})
		if m["status"] != "filtered" {
			t.Errorf("status = %v, want filtered", m["status"])
		}
		got, ok := m["filteredAtStep"]
		if !ok {
			t.Fatalf("filtered event (step %d) omitted filteredAtStep", step)
		}
		if int(got.(float64)) != step {
			t.Errorf("filteredAtStep = %v, want %d", got, step)
		}
	}
	// A non-filtered event does not carry filteredAtStep.
	if m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusPassed, FilteredAtStep: 2}}); func() bool { _, ok := m["filteredAtStep"]; return ok }() {
		t.Error("non-filtered event logged filteredAtStep")
	}
}

// An errored event logs its error string; every known status maps to its token
// and an out-of-range status (or nil Result) is "unknown".
func TestOnProcessComplete_StatusMapping(t *testing.T) {
	if m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusErrored, Error: "boom"}}); m["status"] != "errored" || m["error"] != "boom" {
		t.Errorf("errored record = %v, want status errored + error boom", m)
	}
	for st, want := range map[contract.Status]string{
		contract.StatusPassed:   "passed",
		contract.StatusFiltered: "filtered",
		contract.StatusErrored:  "errored",
		contract.StatusUnknown:  "unknown",
		contract.Status(99):     "unknown",
	} {
		if m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: st}}); m["status"] != want {
			t.Errorf("status(%d) = %v, want %q", st, m["status"], want)
		}
	}
	// A nil Result is defensive: status "unknown", no panic, returns nil.
	if m := record(t, contract.ProcessEvent{Timestamp: time.Now()}); m["status"] != "unknown" {
		t.Errorf("nil Result status = %v, want unknown", m["status"])
	}
}

// A zero Timestamp is omitted like every other empty field — status stays the
// always-present anchor, so a record never carries a misleading epoch-zero time.
func TestOnProcessComplete_ZeroTimestampOmitted(t *testing.T) {
	m := record(t, contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusPassed}})
	if _, ok := m["timestamp"]; ok {
		t.Errorf("zero Timestamp must be omitted, not logged as epoch-zero: %v", m["timestamp"])
	}
	if m["status"] != "passed" {
		t.Errorf("status anchor missing from %v", m)
	}
}

// A nil logger falls back to slog.Default() — a zero-config observer never panics.
func TestNew_NilLoggerDoesNotPanic(t *testing.T) {
	// Route the default logger to discard so the test emits no stderr noise.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	obs := logobserver.New(nil)
	if err := obs.OnProcessComplete(context.Background(), contract.ProcessEvent{Result: &contract.Result{Status: contract.StatusPassed}}); err != nil {
		t.Fatalf("nil-logger observer returned %v", err)
	}
}
