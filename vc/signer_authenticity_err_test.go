package vc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// phaseLifecycle answers every suite with one phase, or with one error.
type phaseLifecycle struct {
	phase vc.LifecyclePhase
	err   error
}

func (l phaseLifecycle) PhaseAt(context.Context, string, time.Time) (vc.LifecyclePhase, error) {
	return l.phase, l.err
}

func (l phaseLifecycle) Entries(context.Context, string) ([]vc.LifecycleEntry, error) {
	return nil, nil
}

// signerSentinels are the causes Err tells a failed result apart by.
var signerSentinels = []error{
	vc.ErrUnsigned,
	vc.ErrProofPolicy,
	vc.ErrCryptosuiteNotRegistered,
	vc.ErrIssuerNotFound,
	vc.ErrSignatureInvalid,
}

// checkSignerErr checks Err for the cases of this file, whose issuer
// verifiers and lifecycle registries wrap no sentinel but ErrIssuerNotFound:
// nil when verified; when failed, it wraps want and no other of
// signerSentinels; when indeterminate, it wraps want and none of them. (Err
// itself promises no more than errors.Is reaching want: an error it wraps from
// an IssuerVerifier or a LifecycleRegistry may wrap others.)
func checkSignerErr(t *testing.T, res *vc.SignerAuthenticityResult, want error) {
	t.Helper()
	if res.State == vc.ConfidenceVerified {
		if res.Err != nil {
			t.Errorf("verified with Err = %v, want nil", res.Err)
		}
		return
	}
	if res.Err == nil {
		t.Fatalf("State = %v with Err nil, want an error", res.State)
	}
	if !errors.Is(res.Err, want) {
		t.Errorf("Err = %v, want an error wrapping %v", res.Err, want)
	}
	var matched []string
	for _, s := range signerSentinels {
		if errors.Is(res.Err, s) {
			matched = append(matched, s.Error())
		}
	}
	switch {
	case res.State == vc.ConfidenceFailed && len(matched) != 1:
		t.Errorf("failed with Err = %v matching %q, want exactly one of the sentinels", res.Err, matched)
	case res.State == vc.ConfidenceIndeterminate && len(matched) != 0:
		t.Errorf("indeterminate with Err = %v matching %q, want none of the sentinels", res.Err, matched)
	}
}

// Err says why signer authenticity is not verified. Each way the evaluation
// can end is a case; the state is the one the rules gave before Err existed.
func TestVerifySignerAuthenticity_ErrTellsTheCause(t *testing.T) {
	transient := errors.New("registry copy is being refreshed")
	registryDown := errors.New("lifecycle registry unreachable")
	_, otherPub := exampleCredential(t, issuerDID, nil)
	setProof := func(member string, value any) func(map[string]any) {
		return func(m map[string]any) { m["proof"].(map[string]any)[member] = value }
	}
	for _, tc := range []struct {
		name      string
		mutate    func(map[string]any)
		setup     func(s *tableIssuers, pub []byte)
		lifecycle vc.LifecycleRegistry
		state     vc.ConfidenceState
		want      error
		noKeyCall bool
	}{
		{name: "verified", state: vc.ConfidenceVerified},
		{name: "a Deprecated suite", lifecycle: phaseLifecycle{phase: vc.PhaseDeprecated}, state: vc.ConfidenceVerified},

		{name: "no proof", mutate: func(m map[string]any) { delete(m, "proof") },
			state: vc.ConfidenceFailed, want: vc.ErrUnsigned, noKeyCall: true},

		{name: "a proof of another type", mutate: setProof("type", "Ed25519Signature2020"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a proof for another purpose", mutate: setProof("proofPurpose", "authentication"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a created time that does not parse", mutate: setProof("created", "yesterday"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a member the signature does not cover", mutate: setProof("nonce", "n-1"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a null proof @context", mutate: setProof("@context", nil),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "no issuer", mutate: func(m map[string]any) {
			m["issuer"] = ""
			m["proof"].(map[string]any)["verificationMethod"] = "#signing"
		}, state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a verificationMethod of another DID", mutate: setProof("verificationMethod", "did:example:other#signing"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a verificationMethod with no fragment", mutate: setProof("verificationMethod", issuerDID),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a cryptosuite no contract names", mutate: setProof("cryptosuite", "ecdsa-rdfc-2019"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a proofValue that does not decode", mutate: setProof("proofValue", "not multibase"),
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a Sunset suite", lifecycle: phaseLifecycle{phase: vc.PhaseSunset},
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a suite in no phase", lifecycle: phaseLifecycle{phase: vc.PhaseUnknown},
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},

		{name: "no key under the verificationMethod", setup: func(s *tableIssuers, _ []byte) { delete(s.keys, vmID) },
			state: vc.ConfidenceFailed, want: vc.ErrIssuerNotFound},
		{name: "a key of another method", setup: func(s *tableIssuers, pub []byte) {
			s.answer = &vc.IssuerKey{ID: issuerDID + "#other", PublicKey: pub, Encoding: did.EncodingMultikey}
		}, state: vc.ConfidenceFailed, want: vc.ErrIssuerNotFound},
		{name: "a key lookup that cannot answer", setup: func(s *tableIssuers, _ []byte) { s.keyErr = transient },
			state: vc.ConfidenceIndeterminate, want: transient},

		{name: "a key that did not sign", setup: func(s *tableIssuers, _ []byte) { s.keys[vmID] = otherPub },
			state: vc.ConfidenceFailed, want: vc.ErrSignatureInvalid},
		{name: "a body changed after signing", mutate: func(m map[string]any) {
			m["credentialSubject"].(map[string]any)["role"] = "approver"
		}, state: vc.ConfidenceFailed, want: vc.ErrSignatureInvalid},
		{name: "a key encoding no contract takes with the proof's shape", setup: func(s *tableIssuers, pub []byte) {
			s.answer = &vc.IssuerKey{ID: vmID, PublicKey: pub, Encoding: did.EncodingJWK}
		}, state: vc.ConfidenceFailed, want: vc.ErrSignatureInvalid},

		{name: "a lifecycle lookup that cannot answer", lifecycle: phaseLifecycle{err: registryDown},
			state: vc.ConfidenceIndeterminate, want: registryDown},

		// An established failure wins over a transient one.
		{name: "a policy failure and a key lookup that cannot answer", mutate: setProof("verificationMethod", "did:example:other#signing"),
			setup: func(s *tableIssuers, _ []byte) { s.keyErr = transient },
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a Sunset suite and a key lookup that cannot answer", lifecycle: phaseLifecycle{phase: vc.PhaseSunset},
			setup: func(s *tableIssuers, _ []byte) { s.keyErr = transient },
			state: vc.ConfidenceFailed, want: vc.ErrProofPolicy, noKeyCall: true},
		{name: "a key that did not sign and a lifecycle lookup that cannot answer", lifecycle: phaseLifecycle{err: registryDown},
			setup: func(s *tableIssuers, _ []byte) { s.keys[vmID] = otherPub },
			state: vc.ConfidenceFailed, want: vc.ErrSignatureInvalid},
		{name: "no key and a lifecycle lookup that cannot answer", lifecycle: phaseLifecycle{err: registryDown},
			setup: func(s *tableIssuers, _ []byte) { delete(s.keys, vmID) },
			state: vc.ConfidenceFailed, want: vc.ErrIssuerNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, pub := exampleCredential(t, issuerDID, tc.mutate)
			s := &tableIssuers{keys: map[string][]byte{vmID: pub}}
			if tc.setup != nil {
				tc.setup(s, pub)
			}
			opts := []vc.VerifierOption{vc.WithIssuerVerifier(s)}
			if tc.lifecycle != nil {
				opts = append(opts, vc.WithLifecycleRegistry(tc.lifecycle))
			}
			res, err := vc.NewVerifier(local.New(), ed25519Verifier(), opts...).VerifySignerAuthenticity(context.Background(), cred)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != tc.state {
				t.Fatalf("State = %v (Err %v), want %v", res.State, res.Err, tc.state)
			}
			if tc.noKeyCall && s.keyCalls != 0 {
				t.Errorf("the key was looked up %d times, want none", s.keyCalls)
			}
			checkSignerErr(t, res, tc.want)
		})
	}
}

// Err keeps what it says of a verified-but-indeterminate result apart from the
// result itself: the proof verified, so the signer's fields stay set.
func TestVerifySignerAuthenticity_ErrLeavesTheSignerFields(t *testing.T) {
	cred, pub := exampleCredential(t, issuerDID, nil)
	s := &tableIssuers{keys: map[string][]byte{vmID: pub}}
	registryDown := errors.New("lifecycle registry unreachable")
	v := vc.NewVerifier(local.New(), ed25519Verifier(), vc.WithIssuerVerifier(s), vc.WithLifecycleRegistry(phaseLifecycle{err: registryDown}))
	res, err := v.VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceIndeterminate || !errors.Is(res.Err, registryDown) {
		t.Fatalf("State, Err = %v, %v; want Indeterminate wrapping the registry's error", res.State, res.Err)
	}
	checkSignerFields(t, res, issuerDID, vmID)
}

// Err is written within a bound, however long what it names is: what it takes
// from the credential, and the issuer verifier's own error, which the default
// writes with the issuer whole.
func TestVerifySignerAuthenticity_ErrIsBounded(t *testing.T) {
	long := "did:dplaax:home.example:org:" + strings.Repeat("x", 64<<10) + ":pipeline:p1:process:s1"
	setProof := func(member string, value any) func(map[string]any) {
		return func(m map[string]any) { m["proof"].(map[string]any)[member] = value }
	}
	for _, tc := range []struct {
		name   string
		issuer string
		mutate func(map[string]any)
		want   error
	}{
		{"a long issuer with no document", long, setProof("verificationMethod", long+"#signing"), vc.ErrIssuerNotFound},
		{"a long verificationMethod of another DID", issuerDID, setProof("verificationMethod", long+"#signing"), vc.ErrProofPolicy},
		{"a long proof type", issuerDID, setProof("type", strings.Repeat("t", 64<<10)), vc.ErrProofPolicy},
		{"a long cryptosuite", issuerDID, setProof("cryptosuite", strings.Repeat("s", 64<<10)), vc.ErrProofPolicy},
		{"a long created time", issuerDID, setProof("created", strings.Repeat("c", 64<<10)), vc.ErrProofPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, _ := exampleCredential(t, tc.issuer, tc.mutate)
			res, err := vc.NewVerifier(local.New(), ed25519Verifier()).VerifySignerAuthenticity(context.Background(), cred)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(res.Err, tc.want) || len(res.Err.Error()) > 1024 {
				t.Errorf("Err = %.300v (%d bytes), want one wrapping %v within 1024 bytes", res.Err, len(errText(res.Err)), tc.want)
			}
		})
	}
}

// longError's text is long. formattingError's text is short, but its
// formatting is long, as an error that implements fmt.Formatter may be.
type longError struct{ wrapped error }

func (e longError) Error() string { return strings.Repeat("e", 64<<10) }
func (e longError) Unwrap() error { return e.wrapped }

type formattingError struct{ wrapped error }

func (e formattingError) Error() string { return "short" }
func (e formattingError) Unwrap() error { return e.wrapped }
func (e formattingError) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, strings.Repeat("f", 64<<10))
}

// failingSignatures is a signature verifier that answers every signature
// with err.
type failingSignatures struct{ err error }

func (s failingSignatures) Verify([]byte, []byte, []byte) (bool, error) { return false, s.err }
func (s failingSignatures) Algorithm() string                           { return "Ed25519" }

// Err is bounded on each way it carries another party's error or what an
// issuer verifier returned, however that party writes its text.
func TestVerifySignerAuthenticity_ErrBoundsWhatOthersReturn(t *testing.T) {
	long := strings.Repeat("x", 64<<10)
	for kind, mk := range map[string]func(wrapped error) error{
		"a long error":       func(w error) error { return longError{w} },
		"a formatting error": func(w error) error { return formattingError{w} },
	} {
		for _, tc := range []struct {
			name      string
			mutate    func(map[string]any)
			setup     func(s *tableIssuers)
			lifecycle vc.LifecycleRegistry
			sig       crypto.Verifier
			state     vc.ConfidenceState
			want      func(err error) error
		}{
			{name: "the issuer verifier's not-found error", setup: func(s *tableIssuers) { s.keyErr = mk(vc.ErrIssuerNotFound) },
				state: vc.ConfidenceFailed, want: func(error) error { return vc.ErrIssuerNotFound }},
			{name: "the issuer verifier's transient error", setup: func(s *tableIssuers) { s.keyErr = mk(nil) },
				state: vc.ConfidenceIndeterminate, want: func(err error) error { return err }},
			{name: "the lifecycle registry's error", lifecycle: phaseLifecycle{err: mk(nil)},
				state: vc.ConfidenceIndeterminate, want: func(err error) error { return err }},
			{name: "the signature verifier's error", sig: failingSignatures{err: mk(nil)},
				state: vc.ConfidenceFailed, want: func(error) error { return vc.ErrSignatureInvalid }},
			{name: "a key of another, long method", setup: func(s *tableIssuers) {
				s.answer = &vc.IssuerKey{ID: issuerDID + "#" + long, PublicKey: s.keys[vmID], Encoding: did.EncodingMultikey}
			}, state: vc.ConfidenceFailed, want: func(error) error { return vc.ErrIssuerNotFound }},
			{name: "a long member outside the signature", mutate: func(m map[string]any) { m["proof"].(map[string]any)[long] = "x" },
				state: vc.ConfidenceFailed, want: func(error) error { return vc.ErrProofPolicy }},
			{name: "a long proofValue that does not decode", mutate: func(m map[string]any) { m["proof"].(map[string]any)["proofValue"] = "z" + long + "0" },
				state: vc.ConfidenceFailed, want: func(error) error { return vc.ErrProofPolicy }},
		} {
			t.Run(kind+": "+tc.name, func(t *testing.T) {
				cred, pub := exampleCredential(t, issuerDID, tc.mutate)
				s := &tableIssuers{keys: map[string][]byte{vmID: pub}}
				if tc.setup != nil {
					tc.setup(s)
				}
				opts := []vc.VerifierOption{vc.WithIssuerVerifier(s)}
				if tc.lifecycle != nil {
					opts = append(opts, vc.WithLifecycleRegistry(tc.lifecycle))
				}
				var sig crypto.Verifier = ed25519Verifier()
				if tc.sig != nil {
					sig = tc.sig
				}
				res, err := vc.NewVerifier(local.New(), sig, opts...).VerifySignerAuthenticity(context.Background(), cred)
				if err != nil {
					t.Fatal(err)
				}
				if res.State != tc.state {
					t.Fatalf("State = %v, want %v", res.State, tc.state)
				}
				var want error
				switch {
				case tc.setup != nil && s.keyErr != nil:
					want = tc.want(s.keyErr)
				case tc.lifecycle != nil:
					want = tc.want(tc.lifecycle.(phaseLifecycle).err)
				case tc.sig != nil:
					want = tc.want(tc.sig.(failingSignatures).err)
				default:
					want = tc.want(nil)
				}
				if !errors.Is(res.Err, want) {
					t.Errorf("Err = %.200v, want an error wrapping %.80v", res.Err, want)
				}
				for how, text := range map[string]string{"Error": res.Err.Error(), "%v": fmt.Sprintf("%v", res.Err), "%+v": fmt.Sprintf("%+v", res.Err)} {
					if len(text) > 1024 {
						t.Errorf("Err through %s is %d bytes, want at most 1024", how, len(text))
					}
				}
			})
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
