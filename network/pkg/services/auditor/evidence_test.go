package auditor_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

// addr builds a well-formed sha256:<hex> content address from a single repeated
// hex digit, readable enough to tell fixtures apart at a glance.
func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

// variantAddr builds a well-formed wire variant id (vc.IsWireVariantID) from a
// single repeated hex digit — the grammar EvidenceService.Register actually
// accepts (P1-A: the wire caller holds StoreVCResult.WireVariantID, never a
// body address, so this is what a real headVariantID argument looks like).
func variantAddr(hexDigit string) string {
	return vc.WireVariantIDFromHex(strings.Repeat(hexDigit, 64))
}

// evidenceFakeReceipts is a spy ReceiptWriter: it records every Put call (head, the
// registrantDID, and a defensive copy of the consumed set, in call order via orderLog) and
// can be configured to return a preset error (e.g. auditor.ErrReceiptConflict).
type evidenceFakeReceipts struct {
	err        error
	calls      []string   // heads Put was called with, in order
	consumed   [][]string // the consumed set for each call, same index as calls
	registrant []string   // the registrantDID for each call, same index as calls
	orderLog   *[]string  // shared with evidenceFakeQueue to observe call order
}

func (f *evidenceFakeReceipts) Put(headHash string, registrantDID string, consumed []string) error {
	f.calls = append(f.calls, headHash)
	f.consumed = append(f.consumed, append([]string(nil), consumed...))
	f.registrant = append(f.registrant, registrantDID)
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

// admittedMap returns an admitted-callback fake mapping variant ids to the
// body address they resolve to — the (bodyAddress, ok, err) shape
// EvidenceService's admission gate needs (vcresolver.Service.ResolveVariantBody's
// production contract). A variant id absent from m is a definitive
// "not admitted" (ok=false), never an error.
func admittedMap(m map[string]string) func(context.Context, string) (string, bool, error) {
	return func(_ context.Context, variantID string) (string, bool, error) {
		body, ok := m[variantID]
		return body, ok, nil
	}
}

// admitNone always answers a definitive "not admitted".
func admitNone(context.Context, string) (string, bool, error) { return "", false, nil }

// TestEvidenceService_UnknownHead_NotAdmitted proves the arbitrary-hash
// amplification guard (D1): a head that has not been admitted into the local
// VC store is rejected before either store is touched.
func TestEvidenceService_UnknownHead_NotAdmitted(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitNone)

	err := svc.Register(context.Background(), variantAddr("a"), []string{addr("b")}, "did:dplaax:reg:org:pipeline")
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
// must never leave a queued head with no receipt. It also proves the P1-A
// keying fix: receipts.Put and queue.Add are keyed by the RESOLVED BODY
// address the admission gate returns, never by the variant id the caller
// supplied — the two are deliberately different strings here so a
// regression back to keying-by-variant fails loudly. And it proves the
// wireauth-proven registrantDID reaches receipts.Put verbatim.
func TestEvidenceService_KnownHead_ReceiptWrittenAndQueued_OrderObservable(t *testing.T) {
	var order []string
	receipts := &evidenceFakeReceipts{orderLog: &order}
	queue := &evidenceFakeQueue{orderLog: &order}
	head := variantAddr("a")
	body := addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	consumed := []string{addr("c"), addr("b")} // deliberately unsorted
	registrant := "did:dplaax:reg:org:pipeline"
	if err := svc.Register(context.Background(), head, consumed, registrant); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(receipts.calls) != 1 || receipts.calls[0] != body {
		t.Fatalf("receipts.Put calls = %v, want exactly [%q] (the BODY address, not the variant id %q)", receipts.calls, body, head)
	}
	if len(queue.calls) != 1 || queue.calls[0] != body {
		t.Fatalf("queue.Add calls = %v, want exactly [%q] (the BODY address, not the variant id %q)", queue.calls, body, head)
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
	if len(receipts.registrant) != 1 || receipts.registrant[0] != registrant {
		t.Errorf("registrantDID passed to Put = %v, want [%q]", receipts.registrant, registrant)
	}
}

// TestEvidenceService_ReceiptConflict_QueueNotTouched proves a receipt
// conflict is terminal: the queue must never be touched when the receipt
// write itself fails.
func TestEvidenceService_ReceiptConflict_QueueNotTouched(t *testing.T) {
	receipts := &evidenceFakeReceipts{err: auditor.ErrReceiptConflict}
	queue := &evidenceFakeQueue{}
	head, body := variantAddr("a"), addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	err := svc.Register(context.Background(), head, []string{addr("b")}, "did:dplaax:reg:org:pipeline")
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
	head, body := variantAddr("a"), addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	if err := svc.Register(context.Background(), head, []string{addr("b")}, "did:dplaax:reg:org:first"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := svc.Register(context.Background(), head, []string{addr("b")}, "did:dplaax:reg:org:second"); err != nil {
		t.Fatalf("replay Register: %v", err)
	}
	if len(queue.calls) != 2 {
		t.Errorf("queue.Add called %d times, want 2 (re-add allowed on replay)", len(queue.calls))
	}
}

// TestEvidenceService_InvalidHeadFormat_InvalidArgument proves a malformed
// head id is rejected before either store or the admission check runs.
func TestEvidenceService_InvalidHeadFormat_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	admitCalled := false
	admitted := func(context.Context, string) (string, bool, error) { admitCalled = true; return "", true, nil }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.Register(context.Background(), "not-a-content-address", []string{addr("b")}, "did:dplaax:reg:org:pipeline")
	if !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("Register: err = %v, want ErrInvalidArgument", err)
	}
	if admitCalled {
		t.Error("admission check called despite a malformed head id")
	}
	if len(receipts.calls) != 0 || len(queue.calls) != 0 {
		t.Error("stores touched despite a malformed head id")
	}
}

// TestEvidenceService_BareBodyAddress_InvalidArgument is the P1-A regression
// check: a bare sha256:<hex> CONTENT ADDRESS — the grammar Register used to
// (wrongly) require, and the grammar every real caller's body address is
// shaped like — must be rejected. A registering caller only ever holds a WIRE
// VARIANT id (StoreVCResult.WireVariantID); admitting a body address here
// would silently accept the wrong identity class.
func TestEvidenceService_BareBodyAddress_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	admitCalled := false
	admitted := func(context.Context, string) (string, bool, error) { admitCalled = true; return "", true, nil }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.Register(context.Background(), addr("a"), []string{addr("b")}, "did:dplaax:reg:org:pipeline")
	if !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("Register(body address): err = %v, want ErrInvalidArgument", err)
	}
	if admitCalled {
		t.Error("admission check called despite a body-address-shaped (not variant-shaped) head")
	}
	if len(receipts.calls) != 0 || len(queue.calls) != 0 {
		t.Error("stores touched despite a body-address-shaped head")
	}
}

// TestEvidenceService_EmptyConsumedSet_InvalidArgument proves an empty/invalid
// consumed set is rejected by the SAME canonicalization CanonicalizeConsumedSet
// enforces for the receipt store — before admission or either store write.
func TestEvidenceService_EmptyConsumedSet_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	head, body := variantAddr("a"), addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	err := svc.Register(context.Background(), head, nil, "did:dplaax:reg:org:pipeline")
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
	admitted := func(context.Context, string) (string, bool, error) { return "", false, boom }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.Register(context.Background(), variantAddr("a"), []string{addr("b")}, "did:dplaax:reg:org:pipeline")
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

// TestEvidenceService_MalformedConsumedMember_InvalidArgument proves the
// content-address grammar is enforced per consumed-set member — an
// authorized caller cannot pin an irreversible first-write-wins receipt with
// a malformed entry (every reader downstream, GetConsumedSources and the
// source-commitment auditor, would then treat it as damage), and a
// "\n"-bearing member specifically cannot smuggle a fake boundary into the
// wireauth handler's deterministic "\n"-joined signed view.
func TestEvidenceService_MalformedConsumedMember_InvalidArgument(t *testing.T) {
	tests := []struct {
		name     string
		consumed []string
	}{
		{"non-address member", []string{addr("a"), "not-a-content-hash"}},
		{"newline-bearing member", []string{addr("a"), addr("b") + "\n"}},
	}
	head, body := variantAddr("f"), addr("h")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipts := &evidenceFakeReceipts{}
			queue := &evidenceFakeQueue{}
			svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

			err := svc.Register(context.Background(), head, tt.consumed, "did:dplaax:reg:org:pipeline")
			if !errors.Is(err, auditor.ErrInvalidArgument) {
				t.Fatalf("Register: err = %v, want ErrInvalidArgument", err)
			}
			if len(receipts.calls) != 0 || len(queue.calls) != 0 {
				t.Error("stores touched despite a malformed consumed-set member")
			}
		})
	}
}

// --- RegisterHead ---

// TestEvidenceService_RegisterHead_AdmittedHead_EnqueuedByBodyAddress_ReceiptsUntouched
// proves RegisterHead's two defining properties vs Register: it shares the
// SAME admission gate and body-address keying (queue.Add is keyed by the
// RESOLVED BODY address, never the variant id), and it writes NO receipt at
// all — the distinguishing property (a head registered here surfaces via
// GetAuditStatus but never via GetConsumedSources).
func TestEvidenceService_RegisterHead_AdmittedHead_EnqueuedByBodyAddress_ReceiptsUntouched(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	head := variantAddr("a")
	body := addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	if err := svc.RegisterHead(context.Background(), head); err != nil {
		t.Fatalf("RegisterHead: %v", err)
	}
	if len(queue.calls) != 1 || queue.calls[0] != body {
		t.Fatalf("queue.Add calls = %v, want exactly [%q] (the BODY address, not the variant id %q)", queue.calls, body, head)
	}
	if len(receipts.calls) != 0 {
		t.Errorf("receipts.Put called %d times, want 0 (RegisterHead writes no receipt)", len(receipts.calls))
	}
}

// TestEvidenceService_RegisterHead_InvalidHeadFormat_InvalidArgument proves a
// malformed head id is rejected before either the admission check or the
// queue runs.
func TestEvidenceService_RegisterHead_InvalidHeadFormat_InvalidArgument(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	admitCalled := false
	admitted := func(context.Context, string) (string, bool, error) { admitCalled = true; return "", true, nil }
	svc := auditor.NewEvidenceService(receipts, queue, admitted)

	err := svc.RegisterHead(context.Background(), "not-a-content-address")
	if !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("RegisterHead: err = %v, want ErrInvalidArgument", err)
	}
	if admitCalled {
		t.Error("admission check called despite a malformed head id")
	}
	if len(queue.calls) != 0 {
		t.Error("queue touched despite a malformed head id")
	}
}

// TestEvidenceService_RegisterHead_UnknownHead_NotAdmitted proves the
// arbitrary-hash amplification guard (D1) holds for RegisterHead too: a head
// not admitted into the local VC store is rejected before the queue is
// touched.
func TestEvidenceService_RegisterHead_UnknownHead_NotAdmitted(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := &evidenceFakeQueue{}
	svc := auditor.NewEvidenceService(receipts, queue, admitNone)

	err := svc.RegisterHead(context.Background(), variantAddr("a"))
	if !errors.Is(err, auditor.ErrHeadNotAdmitted) {
		t.Fatalf("RegisterHead: err = %v, want ErrHeadNotAdmitted", err)
	}
	if len(queue.calls) != 0 {
		t.Errorf("queue.Add called %d times, want 0", len(queue.calls))
	}
}

// TestEvidenceService_RegisterHead_DuplicateRegistration_Idempotent pins the
// Task-1-discovered AuditQueue.Add idempotency semantic at the SERVICE level
// (not just the queue's own unit tests, queue_test.go): re-registering a
// CURRENTLY QUEUED head is a no-op that preserves the existing attempt count
// and does not duplicate the entry — RegisterHead must not defeat this by,
// e.g., removing and re-adding. Uses a REAL auditor.MemQueue (not the spy
// above) since only a real AuditQueue implementation actually carries the
// Attempts state this test observes.
func TestEvidenceService_RegisterHead_DuplicateRegistration_Idempotent(t *testing.T) {
	receipts := &evidenceFakeReceipts{}
	queue := auditor.NewMemQueue()
	head, body := variantAddr("a"), addr("h")
	svc := auditor.NewEvidenceService(receipts, queue, admittedMap(map[string]string{head: body}))

	if err := svc.RegisterHead(context.Background(), head); err != nil {
		t.Fatalf("first RegisterHead: %v", err)
	}
	// Simulate the runner having attempted the audit once before the caller
	// re-registers the same, still-queued head.
	if err := queue.IncrementAttempt(body); err != nil {
		t.Fatalf("IncrementAttempt: %v", err)
	}
	if err := svc.RegisterHead(context.Background(), head); err != nil {
		t.Fatalf("duplicate RegisterHead: %v", err)
	}
	cands, err := queue.ListNewest(10)
	if err != nil {
		t.Fatalf("ListNewest: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("queue has %d candidates, want exactly 1 (re-add of a currently-queued head must not duplicate)", len(cands))
	}
	if cands[0].HeadHash != body {
		t.Errorf("queued head = %q, want the BODY address %q", cands[0].HeadHash, body)
	}
	if cands[0].Attempts != 1 {
		t.Errorf("Attempts = %d, want 1 (duplicate registration must not reset the attempt counter)", cands[0].Attempts)
	}
}
