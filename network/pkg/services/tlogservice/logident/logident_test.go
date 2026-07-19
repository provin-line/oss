package logident_test

import (
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
)

const (
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	processDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
	ownerDIDStr = "did:dplaax:poc.dplaax.dev:org:acme"
)

func TestKind_Emission(t *testing.T) {
	k, err := logident.Kind(pipelineDID)
	if err != nil {
		t.Fatalf("Kind(%q): %v", pipelineDID, err)
	}
	if k != logident.KindEmission {
		t.Errorf("Kind = %q, want %q", k, logident.KindEmission)
	}
}

func TestKind_SinkReceipt(t *testing.T) {
	id := "sink-receipt:" + processDID
	k, err := logident.Kind(id)
	if err != nil {
		t.Fatalf("Kind(%q): %v", id, err)
	}
	if k != logident.KindSinkReceipt {
		t.Errorf("Kind = %q, want %q", k, logident.KindSinkReceipt)
	}
}

func TestKind_SinkReject(t *testing.T) {
	id := "sink-reject:" + processDID
	k, err := logident.Kind(id)
	if err != nil {
		t.Fatalf("Kind(%q): %v", id, err)
	}
	if k != logident.KindSinkReject {
		t.Errorf("Kind = %q, want %q", k, logident.KindSinkReject)
	}
}

// TestKind_FailClosed covers every malformed shape Kind must reject: empty,
// unknown prefix, wrong DID kind at each position, and syntactically invalid
// DIDs. Kind never returns a kind alongside a non-nil error.
func TestKind_FailClosed(t *testing.T) {
	cases := map[string]string{
		"empty":                              "",
		"owner DID is not an emission log":   ownerDIDStr,
		"process DID is not an emission log": processDID,
		"wrong DID method":                   "did:web:example.com",
		"not a DID at all":                   "not-a-did",
		"unsupported account type":           "did:dplaax:poc.dplaax.dev:user:acme:pipeline:p1",
		"sink-receipt empty suffix":          "sink-receipt:",
		"sink-receipt non-DID suffix":        "sink-receipt:not-a-did",
		"sink-receipt pipeline suffix":       "sink-receipt:" + pipelineDID,
		"sink-receipt owner suffix":          "sink-receipt:" + ownerDIDStr,
		"sink-reject empty suffix":           "sink-reject:",
		"sink-reject non-DID suffix":         "sink-reject:not-a-did",
		"sink-reject pipeline suffix":        "sink-reject:" + pipelineDID,
		"unknown prefix":                     "sink-other:" + processDID,
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			k, err := logident.Kind(id)
			if err == nil {
				t.Fatalf("Kind(%q) = %q, nil, want an error", id, k)
			}
			if !errors.Is(err, logident.ErrInvalidLogID) {
				t.Errorf("Kind(%q) err = %v, want wrapping ErrInvalidLogID", id, err)
			}
			if k != "" {
				t.Errorf("Kind(%q) returned kind %q alongside an error, want empty", id, k)
			}
		})
	}
}

func TestOwnerDID_Emission(t *testing.T) {
	owner, err := logident.OwnerDID(pipelineDID)
	if err != nil {
		t.Fatalf("OwnerDID(%q): %v", pipelineDID, err)
	}
	if owner != pipelineDID {
		t.Errorf("OwnerDID = %q, want the id itself %q", owner, pipelineDID)
	}
}

func TestOwnerDID_SinkReceipt(t *testing.T) {
	id := "sink-receipt:" + processDID
	owner, err := logident.OwnerDID(id)
	if err != nil {
		t.Fatalf("OwnerDID(%q): %v", id, err)
	}
	if owner != processDID {
		t.Errorf("OwnerDID = %q, want suffix %q", owner, processDID)
	}
}

func TestOwnerDID_SinkReject(t *testing.T) {
	id := "sink-reject:" + processDID
	owner, err := logident.OwnerDID(id)
	if err != nil {
		t.Fatalf("OwnerDID(%q): %v", id, err)
	}
	if owner != processDID {
		t.Errorf("OwnerDID = %q, want suffix %q", owner, processDID)
	}
}

func TestOwnerDID_FailClosed(t *testing.T) {
	cases := []string{
		"",
		ownerDIDStr,
		"sink-receipt:" + pipelineDID,
		"sink-reject:not-a-did",
		"did:web:example.com",
	}
	for _, id := range cases {
		if owner, err := logident.OwnerDID(id); err == nil {
			t.Errorf("OwnerDID(%q) = %q, nil, want an error", id, owner)
		} else if !errors.Is(err, logident.ErrInvalidLogID) {
			t.Errorf("OwnerDID(%q) err = %v, want wrapping ErrInvalidLogID", id, err)
		}
	}
}

func TestSignerBase_StripsFragment(t *testing.T) {
	cases := []struct {
		signedBy string
		want     string
	}{
		{processDID + "#signing", processDID},
		{processDID + "#auth", processDID},
		{pipelineDID + "#signing", pipelineDID},
	}
	for _, c := range cases {
		base, err := logident.SignerBase(c.signedBy)
		if err != nil {
			t.Fatalf("SignerBase(%q): %v", c.signedBy, err)
		}
		if base != c.want {
			t.Errorf("SignerBase(%q) = %q, want %q", c.signedBy, base, c.want)
		}
	}
}

// TestSignerBase_FailClosed asserts the documented decision: a fragmentless
// SignedBy is rejected, not accepted as its own base. This mirrors the
// existing verification-method base-DID split used throughout the codebase
// (didregistry.verifyDocProof, delegation.Verify, vc.Verifier), which all
// treat strings.Cut(vm, "#") returning found=false as invalid rather than as
// an identity base.
func TestSignerBase_FailClosed(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"no fragment":              processDID,
		"empty base":               "#signing",
		"malformed base DID":       "not-a-did#signing",
		"unsupported account type": "did:dplaax:poc.dplaax.dev:user:acme#signing",
		"wrong method":             "did:web:example.com#signing",
	}
	for name, signedBy := range cases {
		t.Run(name, func(t *testing.T) {
			base, err := logident.SignerBase(signedBy)
			if err == nil {
				t.Fatalf("SignerBase(%q) = %q, nil, want an error", signedBy, base)
			}
			if !errors.Is(err, logident.ErrInvalidSignedBy) {
				t.Errorf("SignerBase(%q) err = %v, want wrapping ErrInvalidSignedBy", signedBy, err)
			}
			if base != "" {
				t.Errorf("SignerBase(%q) returned base %q alongside an error, want empty", signedBy, base)
			}
		})
	}
}
