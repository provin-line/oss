// Tranche 2 of the dplaax conformance harness: behavior-fixture families driven
// against real implementation seams. Registration lives in allvectors_test.go;
// each runner takes an already-loaded vector.
//
// Some tranche-2 vectors have no drivable implementation surface and stay in
// the skip ledger with a blocked-on reason rather than a runner — the coverage
// guard keeps them visible (see allvectors_test.go): resolver-006 (no eviction
// API exists, so the forbidden Resolved->NotFound transition cannot be
// constructed) and resolver-007 (no batch-lookup RPC in vc.proto). Those are
// recorded gaps, not silent omissions.
package conformance_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/evidence"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	schemastore "github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	vcfilestore "github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/tlog/filelog"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// --- commitment.store.persistence (commitment-012) ---
//
// The durable evidence substrate must survive a process restart. Driven exactly
// per filestore's own proven restart pattern: store under a temp dir, then open
// a SECOND store instance over the same dir (no shared in-memory state — the
// restart) and resolve. The vector's key is a placeholder with no reconstructable
// preimage, so the driver stores a real fixture credential and looks it up by its
// own content address; the property under test (survives restart -> Resolved) is
// key-agnostic. memstore would fail this same test — the negative control.
func runCommitmentPersistence(t *testing.T, v dplaaxVector) {
	var e struct {
		State string `json:"state"`
	}
	mustParse(t, v.Expect, &e)

	dir := t.TempDir()
	s, err := vcfilestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cred, _ := signedFixtureCred(t)
	hash, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := s.Put(hash, cred); err != nil {
		t.Fatalf("Put: %v", err)
	}

	restarted, err := vcfilestore.NewStore(dir) // a fresh instance over the same dir
	if err != nil {
		t.Fatalf("NewStore (restart): %v", err)
	}
	_, getErr := restarted.Get(hash)
	resolved := getErr == nil
	if want := e.State == "Resolved"; resolved != want {
		t.Errorf("post-restart Get resolved=%v (err=%v), want state %q", resolved, getErr, e.State)
	}
}

// --- resolver.address.form (resolver-001, 002) ---
//
// A content address is sha256 over the proof-excluded canonical body: the key
// MUST equal the recomputed hash of the served body. resolver-002 carries a
// deliberately-wrong key and must be rejected. Drives the real vc.Hash.
func runResolverAddress(t *testing.T, v dplaaxVector) {
	var input struct {
		Key  string `json:"key"`
		Body string `json:"body"`
	}
	mustParse(t, v.Input, &input)
	match := credAddressesTo(t, []byte(input.Body), input.Key)
	if want := expectString(t, v); match != (want == "accept") {
		t.Errorf("address match=%v, want %s", match, want)
	}
}

// --- resolver.immutability (resolver-003) ---
//
// The same key must always return the same document. Each returned body MUST
// content-address to the queried key; a second lookup returning a different body
// (different outputHash) recomputes to a different hash — the immutability
// violation the vector rejects.
func runResolverImmutability(t *testing.T, v dplaaxVector) {
	var input struct {
		Sequence []struct {
			Op           string `json:"op"`
			Key          string `json:"key"`
			ReturnedBody string `json:"returned_body"`
		} `json:"sequence"`
	}
	mustParse(t, v.Input, &input)
	allConsistent := true
	for _, step := range input.Sequence {
		if step.Op != "lookup" {
			continue
		}
		if !credAddressesTo(t, []byte(step.ReturnedBody), step.Key) {
			allConsistent = false
		}
	}
	if want := expectString(t, v); allConsistent != (want == "accept") {
		t.Errorf("all returned bodies content-address to their key=%v, want %s", allConsistent, want)
	}
}

// --- resolver.body.encoding (resolver-008) ---
//
// The served body is base64url (unpadded). Decode, then it must content-address
// to the entry hash. Drives real base64url + vc.Hash.
func runResolverBodyEncoding(t *testing.T, v dplaaxVector) {
	var input struct {
		Entry struct {
			Hash  string `json:"hash"`
			State string `json:"state"`
			Body  string `json:"body"`
		} `json:"entry"`
	}
	mustParse(t, v.Input, &input)
	raw, err := base64.RawURLEncoding.DecodeString(input.Entry.Body)
	if err != nil {
		if expectString(t, v) == "accept" {
			t.Errorf("base64url decode of an accept vector failed: %v", err)
		}
		return
	}
	match := credAddressesTo(t, raw, input.Entry.Hash)
	if want := expectString(t, v); match != (want == "accept") {
		t.Errorf("decoded body content-addresses to entry hash=%v, want %s", match, want)
	}
}

// --- resolver.states (resolver-004, 005) ---
//
// A resolver's lookup state maps to a confidence: Unavailable (transient) ->
// indeterminate, NotFound (definitive) -> failed. Driven through the real
// vc.Verifier confidence discipline: a fake resolver returns a transient error
// (Unavailable) or one wrapping resolver.ErrNotFound (NotFound), and the
// verifier's weakest-link overall reflects the state. This exercises the
// DID-resolution axis — the one resolver in the tree that implements the full
// Resolved/Unavailable/NotFound trichotomy (VC-content consumers fold both
// misses to indeterminate; see gap-backlog).
func runResolverStates(t *testing.T, v dplaaxVector) {
	var input struct {
		ResolverState string `json:"resolver_state"`
	}
	mustParse(t, v.Input, &input)

	var r resolver.Resolver
	switch input.ResolverState {
	case "Unavailable":
		r = errResolver{err: errors.New("resolver: transport failure")}
	case "NotFound":
		r = errResolver{err: resolver.ErrNotFound}
	default:
		t.Fatalf("unhandled resolver_state %q", input.ResolverState)
	}

	cred, _ := signedFixtureCred(t)
	res, err := vc.NewVerifier(r, ed25519.Verifier{}).Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, want := res.Overall, expectConfidence(t, v); got != want {
		t.Errorf("Overall = %v, want %v (axes %+v)", got, want, res.Axes)
	}
}

// errResolver is a resolver.Resolver that fails every lookup with a fixed error,
// used to drive the resolver-state -> confidence mapping.
type errResolver struct{ err error }

func (e errResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, e.err
}

// --- registry.append-only (registry-001, 002) ---
//
// A registered (name, version) is immutable: a second commit of the same version
// with different content MUST be rejected (registry-001), and deprecation is a
// soft flag that retains the body (registry-002). Driven against the real
// file-backed yamlstore, whose Save enforces the version key with O_EXCL. Notes:
// the vector's key "schema/orders" is sanitized (yamlstore rejects "/" in a name
// for path-traversal safety), and this drives the store layer directly — the
// production schemaregistry.Service.Register auto-computes versions and cannot
// express a caller-chosen re-committed version (recorded in gap-backlog).
func runRegistry(t *testing.T, v dplaaxVector) {
	var input struct {
		Sequence []struct {
			Op          string `json:"op"`
			Key         string `json:"key"`
			Version     string `json:"version"`
			ContentHash string `json:"contentHash"`
		} `json:"sequence"`
	}
	mustParse(t, v.Input, &input)
	st := yamlstore.New(t.TempDir())

	switch vecNum(t, v.ID) {
	case 1: // two commits of the same version with different content -> reject
		var lastErr error
		for _, step := range input.Sequence {
			if step.Op != "commit" {
				t.Fatalf("registry-001: unexpected op %q", step.Op)
			}
			lastErr = st.Save(&schemastore.Schema{
				Name:       registryName(step.Key),
				Version:    step.Version,
				SchemaBody: []byte(step.ContentHash),
			})
		}
		rejected := errors.Is(lastErr, schemastore.ErrExists)
		if want := expectString(t, v); rejected != (want == "reject") {
			t.Errorf("second commit rejected=%v (err=%v), want %s", rejected, lastErr, want)
		}
	case 2: // commit -> deprecate -> get: body retained, flag set
		var name, version string
		for _, step := range input.Sequence {
			switch step.Op {
			case "commit":
				name, version = registryName(step.Key), step.Version
				if err := st.Save(&schemastore.Schema{Name: name, Version: version, SchemaBody: []byte(step.ContentHash)}); err != nil {
					t.Fatalf("commit: %v", err)
				}
			case "deprecate":
				if err := st.Deprecate(registryName(step.Key), step.Version); err != nil {
					t.Fatalf("deprecate: %v", err)
				}
			case "get":
				got, err := st.Get(registryName(step.Key), step.Version)
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				var e struct {
					ContentHash string `json:"contentHash"`
					Deprecated  bool   `json:"deprecated"`
				}
				mustParse(t, v.Expect, &e)
				if string(got.SchemaBody) != e.ContentHash {
					t.Errorf("retained body = %q, want %q", got.SchemaBody, e.ContentHash)
				}
				if got.Deprecated != e.Deprecated {
					t.Errorf("deprecated = %v, want %v", got.Deprecated, e.Deprecated)
				}
			default:
				t.Fatalf("registry-002: unexpected op %q", step.Op)
			}
		}
	default:
		t.Fatalf("registry runner: no branch for %s", v.ID)
	}
}

// registryName sanitizes a vector's schema key for the file-backed store, which
// rejects "/" in a name (path-traversal defense). The append-only property under
// test is orthogonal to the name spelling.
func registryName(key string) string {
	return strings.ReplaceAll(key, "/", "-")
}

// --- chain.trigger.retention (chain-001..005) ---
//
// A single-conformant-predecessor trigger MUST carry previousCredential; any
// other trigger MUST be a chain origin (no previousCredential). There is no
// runtime trigger-classifier to call — the decision is embodied by which static
// process type is deployed (pipeline/chained vs pipeline/source). The driver
// therefore pins the wire-shape invariant the classifier must guarantee, read
// through the real cred.PreviousCredential accessor. chain-005 is fan-out: N
// credentials off one predecessor, all sharing that previousCredential.
//
// TODO: re-point at a runtime trigger classifier if one is ever exported
// (gap-backlog: chain trigger classification has no callable seam today).
func runChainTrigger(t *testing.T, v dplaaxVector) {
	var input struct {
		Trigger     string            `json:"trigger"`
		Credential  json.RawMessage   `json:"credential"`
		Credentials []json.RawMessage `json:"credentials"`
	}
	mustParse(t, v.Input, &input)
	preserving := input.Trigger == "single-conformant-event"

	var accept bool
	if len(input.Credentials) > 0 {
		accept = true
		prev := ""
		for i, raw := range input.Credentials {
			p := mustCred(t, raw).PreviousCredential()
			if p == "" {
				accept = false // a preserving fan-out member must carry a predecessor
			}
			if i == 0 {
				prev = p
			} else if p != prev {
				accept = false // fan-out is off a SINGLE predecessor
			}
		}
		accept = accept && preserving
	} else {
		hasPrev := mustCred(t, input.Credential).PreviousCredential() != ""
		accept = hasPrev == preserving
	}
	if want := expectString(t, v); accept != (want == "accept") {
		t.Errorf("trigger/shape accept=%v, want %s", accept, want)
	}
}

// --- audit.attribution.segment / origin-default (audit-001..004) ---
//
// Attribution resolves each chain segment's issuer to its Owner DID, and
// attributes everything preceding the chain origin to the origin's Owner
// (unconditionally — a source commitment does not shed it). On the did:dplaax
// plane the Owner is a structural prefix of the issuer, so the driver composes
// the real dplaax.Parse().OwnerDID() over each segment. No exported "attribution"
// function exists in the tree (recorded in gap-backlog); this pins the vectors
// against the real structural-owner derivation.
func runAuditAttribution(t *testing.T, v dplaaxVector) {
	var input struct {
		Chain       []json.RawMessage `json:"chain"`
		Controllers map[string]string `json:"controllers"`
	}
	mustParse(t, v.Input, &input)
	var e struct {
		Attribution struct {
			Segments []struct {
				Index int    `json:"index"`
				Owner string `json:"owner"`
			} `json:"segments"`
			PreChain string `json:"pre_chain"`
		} `json:"attribution"`
	}
	mustParse(t, v.Expect, &e)

	if len(e.Attribution.Segments) != len(input.Chain) {
		t.Fatalf("expect has %d segments, chain has %d", len(e.Attribution.Segments), len(input.Chain))
	}
	wantOwner := make(map[int]string, len(e.Attribution.Segments))
	for _, s := range e.Attribution.Segments {
		wantOwner[s.Index] = s.Owner
	}

	originIndex := -1
	for i, raw := range input.Chain {
		cred := mustCred(t, raw)
		structural := ownerOf(t, cred.Issuer())
		if structural != wantOwner[i] {
			t.Errorf("segment %d owner = %q, want %q", i, structural, wantOwner[i])
		}
		// Cross-check the explicit controller chain the vector supplies against
		// the structural prefix derivation. On the did:dplaax plane they must
		// agree; asserting it future-proofs a vector where a controller is not
		// the issuer's structural parent (which structural derivation alone
		// would silently miss).
		if len(input.Controllers) > 0 {
			if viaCtl := ownerViaControllers(input.Controllers, cred.Issuer()); viaCtl != structural {
				t.Errorf("segment %d: controllers-derived owner %q != structural owner %q", i, viaCtl, structural)
			}
		}
		if cred.PreviousCredential() == "" {
			originIndex = i
		}
	}
	if originIndex < 0 {
		t.Fatal("no chain origin: every credential carries previousCredential")
	}
	originOwner := ownerOf(t, mustCred(t, input.Chain[originIndex]).Issuer())
	if originOwner != e.Attribution.PreChain {
		t.Errorf("pre_chain = %q, want %q", originOwner, e.Attribution.PreChain)
	}
}

// ownerOf structurally reduces a did:dplaax issuer to its Owner DID.
func ownerOf(t *testing.T, issuer string) string {
	t.Helper()
	d, err := dplaax.Parse(issuer)
	if err != nil {
		t.Fatalf("parse issuer %q: %v", issuer, err)
	}
	return d.OwnerDID().String()
}

// ownerViaControllers walks the explicit controller chain from issuer to its
// fixpoint (an id with no controller entry is the Owner), cycle-guarded.
func ownerViaControllers(controllers map[string]string, issuer string) string {
	seen := map[string]bool{}
	cur := issuer
	for {
		next, ok := controllers[cur]
		if !ok || seen[cur] {
			return cur
		}
		seen[cur] = true
		cur = next
	}
}

// --- process catalog (process-005, 006) ---
//
// The wire-shape process vectors: process-005 (a sink receipt MUST be wire-valid,
// reference its upstream via previousCredential, and — as the provin:sink-receipt
// identity claim — transform nothing: inputHash == outputHash) and process-006 (a
// Custom Process at a chain origin MUST NOT carry previousCredential). process-004
// (verify sequencing) is driven separately against the real sink runtime
// (runProcessSinkVerify); the catalog/behavior-classification vectors
// (process-001..003) have no callable seam and stay in the skip ledger.
func runProcess(t *testing.T, v dplaaxVector) {
	var input struct {
		ProcessType string          `json:"process_type"`
		ChainRole   string          `json:"chain_role"`
		Credential  json.RawMessage `json:"credential"`
	}
	mustParse(t, v.Input, &input)
	want := expectString(t, v)

	switch vecNum(t, v.ID) {
	case 5: // sink.receipt: wire-valid, carries previousCredential, transforms nothing
		var cred vc.PipelinePassCredential
		if err := cred.UnmarshalJSON(input.Credential); err != nil {
			if want != "reject" {
				t.Errorf("decode rejected an accept vector: %v", err)
			}
			return
		}
		conforms := cred.ValidateWireForm() == nil && cred.PreviousCredential() != ""
		if conforms != (want == "accept") {
			t.Errorf("receipt conforms (wire-form + previousCredential)=%v, want %s", conforms, want)
		}
		if want == "accept" {
			// The receipt's identity shape (folded from the standalone
			// TestDplaaxProcessSinkReceipt): the sink-receipt claim over an
			// input==output hash — a receipt attests consumption, transforms nothing.
			subject, err := cred.Subject()
			if err != nil {
				t.Fatalf("receipt subject: %v", err)
			}
			if subject.TransformationClaim != vc.ClaimSinkReceipt {
				t.Errorf("receipt transformationClaim = %q, want %q", subject.TransformationClaim, vc.ClaimSinkReceipt)
			}
			if subject.InputHash != subject.OutputHash {
				t.Errorf("receipt inputHash %q != outputHash %q (a receipt transforms nothing)", subject.InputHash, subject.OutputHash)
			}
		}
	case 6: // custom.interop: a chain origin MUST NOT carry previousCredential
		hasPrev := mustCred(t, input.Credential).PreviousCredential() != ""
		var ok bool
		switch input.ChainRole {
		case "origin":
			ok = !hasPrev
		default: // a continuing Custom Process MUST retain previousCredential (not exercised here)
			ok = hasPrev
		}
		if ok != (want == "accept") {
			t.Errorf("custom-process role=%q hasPrev=%v ok=%v, want %s", input.ChainRole, hasPrev, ok, want)
		}
	default:
		t.Fatalf("process runner: no branch for %s (005/006 are wire-shape; 004 is runProcessSinkVerify; 001-003 are ledgered skips)", v.ID)
	}
}

// --- process.sink.verify (process-004) ---
//
// process.sink.verify: a Sink Process MUST NOT terminate (deliver externally)
// without verifying the received chain. The vector's input is an op-SEQUENCE —
// [receive, terminate] with no verify step, expect: reject — describing a
// NON-conformant sink. That sink cannot be instantiated from the real runtime
// (sink.Process always calls Verifier.Verify before Writer.Write), so the
// invariant is pinned positively against a real sink.Processor: an
// order-recording Verifier and Writer share one op trace, and a bound envelope
// driven through the sink MUST record "verify" strictly before "write". A
// refactor that terminated without verifying (write before, or without, verify)
// reorders the trace to ["write", …] and fails here — the exact regression the
// vector guards. Unblocked by the sink production/archival slice (PR #7), which
// gave the sink its injectable Verifier/Writer seams; before it, no instrumented
// sink runtime existed to drive.
//
// Two teeth beyond ordering: the driver asserts the sink verified the RECEIVED
// credential (identity, not just that some verify ran — else a regression to
// Verify(ctx, nil) or a substituted credential would still pass), and it ties
// back to THIS vector's forbidden shape (the input sequence carries no verify
// op). It drives both the fail-closed production kind (writes only a Verified
// verdict) and the lenient observation-only kind (writes regardless of verdict):
// verify precedes write in BOTH, because process.sink.verify is about the
// presence/sequencing of the verify step, never the verdict policy.
func runProcessSinkVerify(t *testing.T, v dplaaxVector) {
	if want := expectString(t, v); want != "reject" {
		t.Fatalf("process-004 expect = %q, want reject (the forbidden receive→terminate with no verify)", want)
	}
	// Bind to this vector's forbidden shape: an op-sequence with no verify step.
	var input struct {
		Sequence []struct {
			Op string `json:"op"`
		} `json:"sequence"`
	}
	mustParse(t, v.Input, &input)
	for _, s := range input.Sequence {
		if s.Op == "verify" {
			t.Fatalf("process-004 vector carries a verify op (%+v); the driver pins the no-verify terminate shape", input.Sequence)
		}
	}

	payload := []byte("process-004 conformance payload")
	cred := sinkBoundCred(t, payload)
	wantHash, err := cred.Hash()
	if err != nil {
		t.Fatalf("hash consumed credential: %v", err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    payload,
		SequenceNo: 1,
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	cases := []struct {
		label   string
		kind    contract.SinkKind
		verdict vc.ConfidenceState
	}{
		{"production/verified", contract.SinkProduction, vc.ConfidenceVerified},
		{"observation/indeterminate", contract.SinkObservationOnly, vc.ConfidenceIndeterminate},
	}
	for _, tc := range cases {
		order := &[]string{}
		verifier := &recordingVerifier{order: order, verdict: tc.verdict}
		proc, err := sink.New(sink.Config{
			Strategy:         contract.VerificationAdjacent,
			Kind:             tc.kind,
			Codec:            envelopecodec.New(),
			Verifier:         verifier,
			Store:            noopIngressStore{},
			Writer:           &recordingWriter{order: order},
			UpstreamEndpoint: "https://example.com/upstream",
		})
		if err != nil {
			t.Fatalf("[%s] sink.New: %v", tc.label, err)
		}
		result, err := proc.Process(context.Background(), wire)
		if err != nil {
			t.Fatalf("[%s] sink.Process: %v", tc.label, err)
		}
		if result.Status != contract.StatusPassed {
			t.Fatalf("[%s] sink Status=%v, want StatusPassed (the terminating path)", tc.label, result.Status)
		}
		if !verifiedBeforeWrote(*order) {
			t.Errorf("[%s] sink terminated without verifying first: op order = %v; process.sink.verify requires verify before the external write", tc.label, *order)
		}
		// The sink must verify the RECEIVED chain — not nil, not a substitute.
		// Ordering alone would still pass a regression to Verify(ctx, nil).
		switch {
		case verifier.gotCred == nil:
			t.Errorf("[%s] sink verified a nil credential — the received chain was not verified", tc.label)
		default:
			gotHash, err := verifier.gotCred.Hash()
			if err != nil {
				t.Errorf("[%s] hash verified credential: %v", tc.label, err)
			} else if gotHash != wantHash {
				t.Errorf("[%s] sink verified credential %s, want the consumed %s (must verify the received chain, not a substitute)", tc.label, gotHash, wantHash)
			}
		}
	}
}

// verifiedBeforeWrote reports whether the recorded op trace ran a verify strictly
// before the (first) external write — the process.sink.verify invariant. Absent
// either op, or write-before-verify, is a violation (false).
func verifiedBeforeWrote(order []string) bool {
	verifyAt, writeAt := -1, -1
	for i, op := range order {
		if op == "verify" && verifyAt == -1 {
			verifyAt = i
		}
		if op == "write" && writeAt == -1 {
			writeAt = i
		}
	}
	return verifyAt != -1 && writeAt != -1 && verifyAt < writeAt
}

// recordingVerifier and recordingWriter append their invocation to a shared op
// trace so a driver can assert the sink's call ORDER, not just its outcome.
// recordingVerifier also captures the credential it was handed (gotCred) so the
// driver can assert the sink verified the RECEIVED chain, not a substitute.
type recordingVerifier struct {
	order   *[]string
	verdict vc.ConfidenceState
	gotCred *vc.PipelinePassCredential
}

func (r *recordingVerifier) Verify(_ context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	*r.order = append(*r.order, "verify")
	r.gotCred = cred
	return &vc.VerifyResult{Overall: r.verdict}, nil
}

type recordingWriter struct{ order *[]string }

func (r *recordingWriter) Write(context.Context, sink.Record) error {
	*r.order = append(*r.order, "write")
	return nil
}

// noopIngressStore accepts every ingress VC — the process-004 driver pins the
// verify→write order, not the store.
type noopIngressStore struct{}

func (noopIngressStore) StoreIngressVC(context.Context, *vc.PipelinePassCredential, string) error {
	return nil
}

// sinkBoundCred builds a credential whose outputHash == sha256(payload) — the
// payload↔credential binding the sink enforces before it writes (Stage 6).
func sinkBoundCred(t *testing.T, payload []byte) *vc.PipelinePassCredential {
	t.Helper()
	sum := sha256.Sum256(payload)
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:upstream",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "upstream",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          "sha256:" + hex.EncodeToString(sum[:]),
		},
	})
	if err != nil {
		t.Fatalf("sinkBoundCred: %v", err)
	}
	return cred
}

// credAddressesTo reports whether body decodes to a credential whose content
// address equals key.
func credAddressesTo(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var cred vc.PipelinePassCredential
	if err := cred.UnmarshalJSON(body); err != nil {
		return false
	}
	h, err := cred.Hash()
	if err != nil {
		return false
	}
	return h == key
}

// --- transfer family (audit-reachable transfer evidence: emission, ingress,
// relationship — the federation-layer domain settled 2026-07-11) ---

// --- transfer.evidence.definition (transfer-001) ---
//
// A credential's emission record and its ingress record must share the same
// content-hash join key: the driver appends the fixture credential's wire
// bytes to an emission log (a tlog, standing in for the emitting process's
// transfer.emission.append-only record) and stores it in the real ingress
// vcfilestore (transfer.ingress.retention), then asserts the credential
// re-derived from EACH side hashes identically to cred.Hash() — the single
// content-hash join key reconciliation uses.
func runTransferEvidenceDefinition(t *testing.T, v dplaaxVector) {
	var e struct {
		Join string `json:"join"`
	}
	mustParse(t, v.Expect, &e)

	cred, _ := signedFixtureCred(t)
	wire, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	wantHash, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// Emission side: the emitting process's append-only emission record.
	emissionLog := memlog.New()
	emitted, err := emissionLog.Append(context.Background(), wire)
	if err != nil {
		t.Fatalf("emission Append: %v", err)
	}
	var emittedCred vc.PipelinePassCredential
	if err := emittedCred.UnmarshalJSON(emitted.Payload); err != nil {
		t.Fatalf("unmarshal emitted record: %v", err)
	}
	emissionHash, err := emittedCred.Hash()
	if err != nil {
		t.Fatalf("emission record hash: %v", err)
	}

	// Ingress side: the real ingress VC store.
	ingress, err := vcfilestore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := ingress.Put(wantHash, cred); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ingress.Get(wantHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ingressHash, err := got.Hash()
	if err != nil {
		t.Fatalf("stored credential hash: %v", err)
	}

	consistent := emissionHash == wantHash && ingressHash == wantHash
	if want := e.Join == "content-hash-consistent"; consistent != want {
		t.Errorf("emission hash %s, ingress key %s (retrieved hash %s), cred hash %s: consistent=%v, want %s",
			emissionHash, wantHash, ingressHash, wantHash, consistent, e.Join)
	}
}

// --- transfer.emission.append-only (transfer-002) ---
//
// The append-only, tamper-evident emission record: rewriting an already-
// recorded ordinal is rejected. Driven against the real filelog — append two
// records, then overwrite the FIRST record's payload directly on disk (the
// "rewrite-recorded-ordinal" op — filelog_test.go's own tamper-fixture
// pattern, reused black-box here) and reopen a second filelog instance over
// the same dir; the reopen's replay verification recomputes every hash and
// must fail on the altered entry.
func runTransferEmissionAppendOnly(t *testing.T, v dplaaxVector) {
	want := expectString(t, v)
	ctx := context.Background()
	dir := t.TempDir()

	fl, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	if _, err := fl.Append(ctx, []byte("emission record 1")); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if _, err := fl.Append(ctx, []byte("emission record 2")); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	// Release the single-opener lock before tampering and reopening.
	if err := fl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := filepath.Join(dir, "log.ndjson")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 recorded lines, got %d", len(lines))
	}
	var entry map[string]any
	// decoder-hygiene-exempt: test-side tamper helper on fixture bytes.
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal recorded entry: %v", err)
	}
	entry["payload"] = base64.StdEncoding.EncodeToString([]byte("rewritten ordinal 0"))
	// canonicalizer-hygiene-exempt: deliberate tamper fixture.
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("re-marshal tampered entry: %v", err)
	}
	lines[0] = string(tampered)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered log: %v", err)
	}

	_, reopenErr := filelog.New(dir) // replay verification runs here
	rejected := reopenErr != nil
	if rejected != (want == "reject") {
		t.Errorf("reopen after rewriting a recorded ordinal rejected=%v (err=%v), want %s", rejected, reopenErr, want)
	}
}

// --- transfer.ingress.retention (transfer-003) ---
//
// A received credential is retained byte-preserving across a process restart
// and is enumerable for audit. Driven exactly like commitment-012's own
// restart pattern (runCommitmentPersistence): store a signed fixture
// credential in the real ingress vcfilestore, open a SECOND store instance
// over the same dir (the restart), Get it back, and assert the retained
// credential's marshaled bytes are byte-identical to what was stored — plus
// assert it is enumerable via ListHashes (vcresolver.Store's enumeration
// primitive; already-existing I1 surface, no new method needed).
func runTransferIngressRetention(t *testing.T, v dplaaxVector) {
	var e struct {
		State string `json:"state"`
	}
	mustParse(t, v.Expect, &e)

	dir := t.TempDir()
	s, err := vcfilestore.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cred, _ := signedFixtureCred(t)
	hash, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	wantBytes, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if err := s.Put(hash, cred); err != nil {
		t.Fatalf("Put: %v", err)
	}

	restarted, err := vcfilestore.NewStore(dir) // a fresh instance over the same dir
	if err != nil {
		t.Fatalf("NewStore (restart): %v", err)
	}
	got, err := restarted.Get(hash)
	if err != nil {
		t.Fatalf("Get (restart): %v", err)
	}
	gotBytes, err := got.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON retrieved: %v", err)
	}
	byteIdentical := string(gotBytes) == string(wantBytes)

	hashes, err := restarted.ListHashes("", 10)
	if err != nil {
		t.Fatalf("ListHashes: %v", err)
	}
	enumerable := false
	for _, h := range hashes {
		if h == hash {
			enumerable = true
		}
	}

	state := "not-retained-byte-identical"
	if byteIdentical && enumerable {
		state = "retained-byte-identical"
	}
	if state != e.State {
		t.Errorf("post-restart retention state = %q (byteIdentical=%v enumerable=%v), want %q", state, byteIdentical, enumerable, e.State)
	}
}

// --- transfer.relationship.record (transfer-004) ---
//
// A counterparty-signed relationship request is retained with its signed
// view and verifying key material across a process restart. Driven against
// the real evidence.Log over a filelog: Record a fully-populated
// evidence.Record, open a SECOND filelog+evidence.Log instance over the same
// dir (the restart), Get(0) it back, and assert the retained Record equals
// the original byte-for-byte (signed view components + KeyMaterial).
func runTransferRelationshipRecord(t *testing.T, v dplaaxVector) {
	var e struct {
		State string `json:"state"`
	}
	mustParse(t, v.Expect, &e)

	ctx := context.Background()
	dir := t.TempDir()

	fl, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	log := evidence.New(fl)
	want := evidence.Record{
		Op:          "RegisterSubscription",
		ViewVersion: wireauth.ViewVersion,
		SignerDID:   "did:dplaax:conf.example:org:sub",
		Nonce:       "n-transfer-004",
		IssuedAt:    "2026-07-11T12:00:00Z",
		Signature:   []byte{0xde, 0xad, 0xbe, 0xef},
		Fields: map[string]any{
			"subscriber_did":   "did:dplaax:conf.example:org:sub",
			"publisher_did":    "did:dplaax:conf.example:org:acme:pipeline:p1",
			"payload_delivery": "inline",
		},
		KeyMaterial: evidence.KeyMaterial{
			Method:    "did:dplaax:conf.example:org:sub#auth",
			PublicKey: []byte{1, 2, 3, 4, 5},
			Type:      "authentication",
		},
	}
	if _, err := log.Record(ctx, want); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fl2, err := filelog.New(dir) // a fresh instance over the same dir (the restart)
	if err != nil {
		t.Fatalf("filelog.New (restart): %v", err)
	}
	defer fl2.Close()
	log2 := evidence.New(fl2)
	got, err := log2.Get(ctx, 0)
	if err != nil {
		t.Fatalf("Get (restart): %v", err)
	}

	state := "not-signed-view-retained"
	if reflect.DeepEqual(got, want) {
		state = "signed-view-retained"
	}
	if state != e.State {
		t.Errorf("post-restart relationship record state = %q, want %q (got %+v, want %+v)", state, e.State, got, want)
	}
}
