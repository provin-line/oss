package auditor_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/auditor"
)

// addr builds a well-formed sha256:<hex> content address from a single repeated
// hex digit, readable enough to tell fixtures apart at a glance.
func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

// evidenceFakeReceipts is a spy ReceiptWriter: it records every Put call (head +
// a defensive copy of the consumed set, in call order via orderLog) and can be
// configured to return a preset error (e.g. auditor.ErrReceiptConflict).
type evidenceFakeReceipts struct {
	err      error
	calls    []string   // heads Put was called with, in order
	consumed [][]string // the consumed set for each call, same index as calls
	orderLog *[]string  // shared with evidenceFakeQueue to observe call order
}

func (f *evidenceFakeReceipts) Put(headHash string, consumed []string) error {
	f.calls = append(f.calls, headHash)
	f.consumed = append(f.consumed, append([]string(nil), consumed...))
	if f.orderLog != nil {
		*f.orderLog = append(*f.orderLog, "put")
	}
	return f.err
}

// evidenceFakeQueue is a spy Registrar: it records every Add call and can be
// configured to return a preset error.
type evidenceFakeQueue struct {
	err      error
	calls    []string
	orderLog *[]string
}

func (f *evidenceFakeQueue) Add(headHash string) error {
	f.calls = append(f.calls, headHash)
	if f.orderLog != nil {
		*f.orderLog = append(*f.orderLog, "add")
	}
	return f.err
}

func admitAll(context.Context, string) (bool, error)  { return true, nil }
func admitNone(context.Context, string) (bool, error) { return false, nil }

// TestEvidenceService_UnknownHead_NotAdmitted proves the arbitrary-hash
// amplification guard (D1): a head that has not been admitted into the local
// VC store is rejected before either store is touched.
func TestEvidenceService_UnknownHead_NotAdmitted(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitNone)

	err := svc.Register(context.Background(), addr("a"), []string{addr("b")})
	if !errors.Is(err, auditor.ErrHeadNotAdmitted) {
		t.Fatalf("Register: err = %v, want ErrHeadNotAdmitted", err)
	}
	if len(receipts.calls) != 0 {
		t.Errorf("receipts.Put called %d times, want 0 (admission gate must run first)", len(receipts.calls))
	}
	if len(queue.calls) != 0 {
		t.Errorf("queue.Add called %d times, want 0", len(queue.calls))
	}
}

// TestEvidenceService_KnownHead_ReceiptWrittenAndQueued_OrderObservable proves
// the composite-write ordering (D1): the receipt is durably recorded BEFORE
// the head is enqueued for audit, never the reverse — a crash between the two
// must never leave a queued head with no receipt.
func TestEvidenceService_KnownHead_ReceiptWrittenAndQueued_OrderObservable(t *testing.T) {
	var order []string
	receipts := &evidenceFakeReceipts{orderLog: &order}
	queue := &evidenceFakeQueue{orderLog: &order}
	svc := auditor.NewEvidenceService(receipts, queue, admitAll)

	head := addr("a")
	consumed := []string{addr("c"), addr("b")} // deliberately unsorted
	if err := svc.Register(context.Background(), head, consumed); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(receipts.calls) != 1 || receipts.calls[0] != head {
		t.Fatalf("receipts.Put calls = %v, want exactly [%q]", receipts.calls, head)
	}
	if len(queue.calls) != 1 || queue.calls[0] != head {
		t.Fatalf("queue.Add calls = %v, want exactly [%q]", queue.calls, head)
	}
	if got, want := order, []string{"put", "add"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("call order = %v, want %v (receipt before enqueue)", got, want)
	}
	// The consumed set reaching the receipt store is the CANONICAL (sorted,
	// deduplicated) form, not the as-submitted order.
	want := []string{addr("b"), addr("c")}
	got := receipts.consumed[0]
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("consumed set passed to Put = %v, want canonical %v", got, want)
	}
}

// TestEvidenceService_ReceiptConflict_QueueNotTouched proves a receipt
// conflict is terminal: the queue must never be touched when the receipt
// write itself fails.
func TestEvidenceService_ReceiptConflict_QueueNotTouched(t *testing.T) {
	receipts := &evidenceFakeReceipts{err: auditor.ErrReceiptConflict}
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitAll)

	err := svc.Register(context.Background(), addr("a"), []string{addr("b")})
	if !errors.Is(err, auditor.ErrReceiptConflict) {
		t.Fatalf("Register: err = %v, want ErrReceiptConflict", err)
	}
	if len(queue.calls) != 0 {
		t.Errorf("queue.Add called %d times, want 0 (conflict must not touch the queue)", len(queue.calls))
	}
}

// TestEvidenceService_IdenticalReplay_QueueReAddAllowed proves a
// canonically-identical replay (the ReceiptStore.Put idempotent no-op path,
// nil error) still reaches queue.Add — re-registering an already-queued head
// is safe because the queue's own Add is idempotent.
func TestEvidenceService_IdenticalReplay_QueueReAddAllowed(t *testing.T) {
	receipts := &evidenceFakeReceipts{} // nil err == the idempotent-replay case
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitAll)

	head := addr("a")
	if err := svc.Register(context.Background(), head, []string{addr("b")}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := svc.Register(context.Background(), head, []string{addr("b")}); err != nil {
		t.Fatalf("replay Register: %v", err)
	}
	if len(queue.calls) != 2 {
		t.Errorf("queue.Add called %d times, want 2 (re-add allowed on replay)", len(queue.calls))
	}
}

// TestEvidenceService_InvalidHeadFormat_InvalidArgument proves a malformed
// head address is rejected before either store or the admission check runs.
func TestEvidenceService_InvalidHeadFormat_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	admitCalled := false
	admitted := func(context.Context, string) (bool, error) { admitCalled = true; return true, nil }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.Register(context.Background(), "not-a-content-address", []string{addr("b")})
	if !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("Register: err = %v, want ErrInvalidArgument", err)
	}
	if admitCalled {
		t.Error("admission check called despite a malformed head address")
	}
	if len(receipts.calls) != 0 || len(queue.calls) != 0 {
		t.Error("stores touched despite a malformed head address")
	}
}

// TestEvidenceService_EmptyConsumedSet_InvalidArgument proves an empty/invalid
// consumed set is rejected by the SAME canonicalization CanonicalizeConsumedSet
// enforces for the receipt store — before admission or either store write.
func TestEvidenceService_EmptyConsumedSet_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitAll)

	err := svc.Register(context.Background(), addr("a"), nil)
	if !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("Register: err = %v, want ErrInvalidArgument", err)
	}
	if len(receipts.calls) != 0 || len(queue.calls) != 0 {
		t.Error("stores touched despite an empty consumed set")
	}
}

// TestEvidenceService_AdmissionCheckError_Surfaces proves a genuine admission
// check FAILURE (e.g. a store I/O error) surfaces distinctly from a definitive
// "not admitted" — it must not be laundered into ErrHeadNotAdmitted.
func TestEvidenceService_AdmissionCheckError_Surfaces(t *testing.T) {
	boom := errors.New("boom: admission store unavailable")
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	admitted := func(context.Context, string) (bool, error) { return false, boom }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.Register(context.Background(), addr("a"), []string{addr("b")})
	if !errors.Is(err, boom) {
		t.Fatalf("Register: err = %v, want it to wrap %v", err, boom)
	}
	if errors.Is(err, auditor.ErrHeadNotAdmitted) {
		t.Error("admission I/O error must not present as ErrHeadNotAdmitted")
	}
	if len(receipts.calls) != 0 || len(queue.calls) != 0 {
		t.Error("stores touched despite an admission check error")
	}
}
