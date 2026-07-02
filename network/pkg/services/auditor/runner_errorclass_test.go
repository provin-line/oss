package auditor

// Integration pin for the resolver-error classification contract through the
// runner lifecycle (review fix FIX-1): a transient registry outage during
// signer/controller DID resolution must yield a RETRYABLE Indeterminate — the
// head stays queued and flips to Verified once the registry is reachable —
// never a terminal Failed, which the runner would dequeue and (with a durable
// status store) pin permanently. Uses the REAL vc.Verifier over a real signed
// credential; only the DID resolver misbehaves.

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// realVerifierCV adapts the real *vc.Verifier to the ChainVerifier seam for an
// origin head: assembling a chain that has no previousCredential is the head
// alone, so no chain-walk dependency is needed (layer rule: network/ does not
// import pipeline/).
type realVerifierCV struct{ v *vc.Verifier }

func (r realVerifierCV) VerifyChain(ctx context.Context, head *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return r.v.VerifyChain(ctx, []*vc.PipelinePassCredential{head})
}

// outageResolver simulates a registry outage: while down, every resolution
// fails with a transport-class error (NOT wrapping resolver.ErrNotFound); when
// up, it delegates to the seeded inner resolver.
type outageResolver struct {
	mu    sync.Mutex
	down  bool
	inner resolver.Resolver
}

func (o *outageResolver) setDown(d bool) { o.mu.Lock(); o.down = d; o.mu.Unlock() }

func (o *outageResolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	o.mu.Lock()
	down := o.down
	o.mu.Unlock()
	if down {
		return nil, errors.New("dial tcp 203.0.113.9:443: connect: connection refused")
	}
	return o.inner.Resolve(ctx, didStr)
}

// ecDoc builds a DID Document; with a non-nil pub it carries an
// AssertionMethod signing key controlled by the subject.
func ecDoc(id, controller string, pub []byte) *did.DIDDocument {
	fields := did.DocumentFields{ID: id, Controller: controller}
	if pub != nil {
		vmID := id + "#signing"
		fields.VerificationMethod = []did.VerificationMethod{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: id,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}}
		fields.AssertionMethod = []string{vmID}
	}
	return did.New(fields)
}

func TestAuditOne_TransientResolverOutage_RetainedThenVerified(t *testing.T) {
	const (
		ecOwner  = "did:dplaax:reg.example:org:acme"
		ecIssuer = ecOwner + ":pipeline:p1:process:s1"
	)
	ctx := context.Background()

	// A real signed origin FirstDrop and its DID graph (Process → Owner).
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := filestore.New(t.TempDir())
	if err := ks.SaveKeyPair(ecIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	cred, err := vc.NewBuilder(ed25519.NewSigner(ks)).BuildFirstDrop(
		ecIssuer, string(keystore.KeyIDSigning), ecIssuer+"#signing",
		vc.CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "s1",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           "sha256:" + strings.Repeat("ab", 32),
			OutputHash:          "sha256:" + strings.Repeat("cd", 32),
		}, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	headHash, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	seeded := local.New()
	seeded.Add(ecDoc(ecIssuer, ecOwner, kp.PublicKey))
	seeded.Add(ecDoc(ecOwner, ecOwner, nil))
	outage := &outageResolver{down: true, inner: seeded}

	q := NewMemQueue()
	if err := q.Add(headHash); err != nil {
		t.Fatalf("queue.Add: %v", err)
	}
	status := NewMemStatusStore()
	r, err := New(q, fakeHeads{m: map[string]*vc.PipelinePassCredential{headHash: cred}},
		realVerifierCV{v: vc.NewVerifier(outage, ed25519.Verifier{})},
		status, fakePool{},
		Config{Interval: time.Hour, BatchSize: 4, MaxAttempts: 5})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Tick 1 — registry outage: a retryable Indeterminate, head retained.
	if err := r.drainOnce(ctx); err != nil {
		t.Fatalf("drainOnce (outage): %v", err)
	}
	rec, ok := status.Get(headHash)
	if !ok {
		t.Fatal("no verdict recorded during the outage")
	}
	if rec.Overall != vc.ConfidenceIndeterminate {
		t.Fatalf("Overall = %v during a transient outage, want Indeterminate (a Failed here would be dequeued as terminal and pinned)", rec.Overall)
	}
	if rec.Axes.SignerAuthenticity != vc.ConfidenceIndeterminate {
		t.Errorf("SignerAuthenticity = %v, want Indeterminate", rec.Axes.SignerAuthenticity)
	}
	if rec.Axes.ChainConsistency != vc.ConfidenceIndeterminate {
		t.Errorf("ChainConsistency = %v, want Indeterminate", rec.Axes.ChainConsistency)
	}
	if rec.Axes.DataIntegrity != vc.ConfidenceVerified {
		t.Errorf("DataIntegrity = %v, want Verified (resolver-independent axis)", rec.Axes.DataIntegrity)
	}
	if q.Len() != 1 {
		t.Fatalf("queue len = %d after the outage tick, want 1 (head retained for retry)", q.Len())
	}

	// Tick 2 — registry reachable again: the verdict flips to Verified and the
	// head dequeues as terminal.
	outage.setDown(false)
	if err := r.drainOnce(ctx); err != nil {
		t.Fatalf("drainOnce (recovered): %v", err)
	}
	rec, ok = status.Get(headHash)
	if !ok {
		t.Fatal("no verdict recorded after recovery")
	}
	if rec.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall = %v after recovery, want Verified", rec.Overall)
	}
	if q.Len() != 0 {
		t.Errorf("queue len = %d after the recovered tick, want 0 (terminal dequeued)", q.Len())
	}
}
