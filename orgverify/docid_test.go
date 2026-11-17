package orgverify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
)

// substituting answers every resolution with doc.
type substituting struct{ doc *did.DIDDocument }

func (s substituting) Resolve(context.Context, string) (*did.DIDDocument, error) { return s.doc, nil }

// Verify refuses a document whose id is not the Owner DID it asked for, even
// one holding the key the DNS record endorses: the document is not the
// Owner's, so the endorsement is not established.
func TestVerify_RefusesTheDocumentOfAnotherDID(t *testing.T) {
	const (
		owner = "did:dplaax:poc.dplaax.dev:org:acme.com"
		other = "did:dplaax:poc.dplaax.dev:org:other.example"
	)
	key := mustKey(t)
	dns := &stubResolver{records: []string{"v=dplaax1; did=" + owner + "; key=" + fingerprintFor(t, owner, key)}}
	r, err := Verify(context.Background(), owner, Options{DNSResolver: dns, DIDResolver: substituting{newOwnerDoc(t, other, key)}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.Level != EndorsementUnreachable || r.Reason != ReasonDocFetchFailed {
		t.Errorf("Level, Reason = %s, %s, want %s, %s", r.Level, r.Reason, EndorsementUnreachable, ReasonDocFetchFailed)
	}
	if r.KeyFingerprint != "" {
		t.Errorf("KeyFingerprint = %q, want none: the document is not the Owner's", r.KeyFingerprint)
	}
	if !strings.Contains(r.Detail, other) || !strings.Contains(r.Detail, owner) {
		t.Errorf("Detail = %q, want it to name both DIDs", r.Detail)
	}
}

// Inspect reports a document whose id is not the Owner DID it asked for as a
// document error, and neither the document nor its key's fingerprint.
func TestInspect_RefusesTheDocumentOfAnotherDID(t *testing.T) {
	const (
		owner = "did:dplaax:poc.dplaax.dev:org:acme.com"
		other = "did:dplaax:poc.dplaax.dev:org:other.example"
	)
	r, err := Inspect(context.Background(), owner, Options{DNSResolver: &stubResolver{}, DIDResolver: substituting{newOwnerDoc(t, other, mustKey(t))}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if r.DocumentError == "" || r.DocumentRetrieved != nil || r.KeyFingerprint != "" {
		t.Errorf("DocumentError %q, DocumentRetrieved %v, KeyFingerprint %q: want an error and neither", r.DocumentError, r.DocumentRetrieved != nil, r.KeyFingerprint)
	}
	if !strings.Contains(r.DocumentError, other) || !strings.Contains(r.DocumentError, owner) {
		t.Errorf("DocumentError = %q, want it to name both DIDs", r.DocumentError)
	}
}

// The id of a document of another DID is named within a bound, however long.
func TestVerify_NamesAnotherDIDsDocumentWithinABound(t *testing.T) {
	const owner = "did:dplaax:poc.dplaax.dev:org:acme.com"
	long := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 64<<10)
	r, err := Verify(context.Background(), owner, Options{DNSResolver: &stubResolver{}, DIDResolver: substituting{newOwnerDoc(t, long, mustKey(t))}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(r.Detail) > 512 || !strings.Contains(r.Detail, fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("Detail = %.200q (%d bytes), want the id's head and length within 512 bytes", r.Detail, len(r.Detail))
	}
}

// failing answers every resolution with err.
type failing struct{ err error }

func (f failing) Resolve(context.Context, string) (*did.DIDDocument, error) { return nil, f.err }

// A resolver's error is written within a bound, however long its text.
func TestVerifyAndInspect_WriteAResolverErrorWithinABound(t *testing.T) {
	const owner = "did:dplaax:poc.dplaax.dev:org:acme.com"
	long := strings.Repeat("e", 64<<10)
	opts := Options{DNSResolver: &stubResolver{}, DIDResolver: failing{errors.New(long)}}
	r, err := Verify(context.Background(), owner, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(r.Detail) > 1024 || !strings.Contains(r.Detail, fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("Verify Detail: %d bytes, want the error's head and length within 1 KiB", len(r.Detail))
	}
	ir, err := Inspect(context.Background(), owner, opts)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(ir.DocumentError) > 1024 || !strings.Contains(ir.DocumentError, fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("Inspect DocumentError: %d bytes, want the error's head and length within 1 KiB", len(ir.DocumentError))
	}
}

// A resolver that answers with neither a document nor an error is refused as
// a document not fetched, and panics nothing.
func TestVerifyAndInspect_RefuseNoDocumentAndNoError(t *testing.T) {
	const owner = "did:dplaax:poc.dplaax.dev:org:acme.com"
	opts := Options{DNSResolver: &stubResolver{}, DIDResolver: failing{nil}}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Verify panicked: %v", r)
			}
		}()
		r, err := Verify(context.Background(), owner, opts)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if r.Level != EndorsementUnreachable || r.Reason != ReasonDocFetchFailed || r.KeyFingerprint != "" {
			t.Errorf("Verify: %s, %s, %q, want %s, %s and no fingerprint", r.Level, r.Reason, r.KeyFingerprint, EndorsementUnreachable, ReasonDocFetchFailed)
		}
	}()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Inspect panicked: %v", r)
			}
		}()
		r, err := Inspect(context.Background(), owner, opts)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if r.DocumentError == "" || r.DocumentRetrieved != nil || r.KeyFingerprint != "" {
			t.Errorf("Inspect: DocumentError %q, DocumentRetrieved %v, KeyFingerprint %q, want an error and neither", r.DocumentError, r.DocumentRetrieved != nil, r.KeyFingerprint)
		}
	}()
}
