package wireauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedTime is a second-precision UTC instant used across the deterministic
// view/sign tests.
func fixedTime() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

// viewAudience is the audience the deterministic view/sign tests sign for.
const viewAudience = "verifier.example"

func TestViewBytesV2Composition(t *testing.T) {
	got, err := viewBytes(ViewVersion, "did:dplaax:a.example:org:o1:pipeline:p1", "b.example", "Op", "n1",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("viewBytes: %v", err)
	}
	want := `{"aud":"b.example","fields":{"k":"v"},"issuedAt":"2026-01-02T03:04:05Z","nonce":"n1","op":"Op","signerDID":"did:dplaax:a.example:org:o1:pipeline:p1","v":2}`
	if string(got) != want {
		t.Errorf("view v2:\n got=%s\nwant=%s", got, want)
	}
}

func TestViewBytes_BindsAudience(t *testing.T) {
	fields := map[string]any{"actor": "did:dplaax:poc:org:acme"}
	a, _ := viewBytes(ViewVersion, "did:dplaax:poc:org:sub", "a.example", "Op", "n1", fixedTime(), fields)
	b, _ := viewBytes(ViewVersion, "did:dplaax:poc:org:sub", "b.example", "Op", "n1", fixedTime(), fields)
	if bytes.Equal(a, b) {
		t.Error("viewBytes does not bind the audience: distinct audiences produced identical bytes")
	}
}

func TestViewBytes_Deterministic(t *testing.T) {
	fields := map[string]any{"actor": "did:dplaax:poc:org:acme", "mode": "by-reference"}
	a, err := viewBytes(ViewVersion, "did:dplaax:poc:org:sub", viewAudience, "RegisterSubscription", "n1", fixedTime(), fields)
	if err != nil {
		t.Fatalf("viewBytes: %v", err)
	}
	b, err := viewBytes(ViewVersion, "did:dplaax:poc:org:sub", viewAudience, "RegisterSubscription", "n1", fixedTime(), fields)
	if err != nil {
		t.Fatalf("viewBytes (2nd): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("viewBytes not deterministic:\n a=%s\n b=%s", a, b)
	}
}

func TestViewBytes_BindsSignerDID(t *testing.T) {
	fields := map[string]any{"actor": "did:dplaax:poc:org:acme"}
	a, _ := viewBytes(ViewVersion, "did:dplaax:poc:org:sub-A", viewAudience, "Op", "n1", fixedTime(), fields)
	b, _ := viewBytes(ViewVersion, "did:dplaax:poc:org:sub-B", viewAudience, "Op", "n1", fixedTime(), fields)
	if bytes.Equal(a, b) {
		t.Error("viewBytes does not bind signerDID: distinct signers produced identical bytes")
	}
	if !strings.Contains(string(a), "sub-A") {
		t.Errorf("signed bytes do not contain signerDID: %s", a)
	}
}

func TestViewBytes_RejectsBadFields(t *testing.T) {
	cases := map[string]map[string]any{
		"nil fields":  nil,
		"int value":   {"n": 1},
		"float value": {"n": 1.5},
		"int64 value": {"n": int64(7)},
		"nested int":  {"o": map[string]any{"n": 3}},
		"array int":   {"a": []any{"ok", 9}},
		"time value":  {"t": fixedTime()},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := viewBytes(ViewVersion, "did:x", viewAudience, "Op", "n1", fixedTime(), fields); !errors.Is(err, ErrInvalidView) {
				t.Errorf("%s: want ErrInvalidView, got %v", name, err)
			}
		})
	}
}

func TestViewBytes_AllowsScalarGrammar(t *testing.T) {
	fields := map[string]any{
		"s":      "string",
		"b":      true,
		"null":   nil,
		"nested": map[string]any{"inner": "v", "flag": false},
		"arr":    []any{"a", "b", nil, true},
	}
	if _, err := viewBytes(ViewVersion, "did:x", viewAudience, "Op", "n1", fixedTime(), fields); err != nil {
		t.Errorf("scalar grammar rejected: %v", err)
	}
}

// capturingSigner records the (did, keyID, data) of the last Sign call and
// returns a deterministic signature, so a test can assert what bytes Sign signed.
type capturingSigner struct {
	did, keyID string
	data       []byte
}

func (s *capturingSigner) Sign(did, keyID string, data []byte) ([]byte, error) {
	s.did, s.keyID = did, keyID
	s.data = append([]byte(nil), data...)
	return append([]byte("sig:"), data...), nil
}

func TestSign_SignsViewBytesWithAuthKey(t *testing.T) {
	cs := &capturingSigner{}
	signerDID := "did:dplaax:poc:org:sub"
	fields := map[string]any{"actor": "did:dplaax:poc:org:acme"}
	proof, err := Sign(cs, "RegisterSubscription", fields, Claims{SignerDID: signerDID, Audience: viewAudience, Nonce: "nonce-1", IssuedAt: fixedTime()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cs.keyID != "auth" {
		t.Errorf("signed with keyID %q, want \"auth\"", cs.keyID)
	}
	want, _ := viewBytes(ViewVersion, signerDID, viewAudience, "RegisterSubscription", "nonce-1", fixedTime(), fields)
	if !bytes.Equal(cs.data, want) {
		t.Errorf("Sign signed unexpected bytes:\n got=%s\nwant=%s", cs.data, want)
	}
	if proof.SignerDID != signerDID || proof.Audience != viewAudience || proof.Nonce != "nonce-1" {
		t.Errorf("proof header mismatch: %+v", proof)
	}
	if !bytes.Equal(proof.Signature, append([]byte("sig:"), want...)) {
		t.Errorf("proof signature mismatch")
	}
}

func TestSign_TruncatesSubSecondIssuedAt(t *testing.T) {
	cs := &capturingSigner{}
	sub := time.Date(2026, 6, 16, 12, 0, 0, 500_000_000, time.UTC) // .5s
	proof, err := Sign(cs, "Op", map[string]any{"a": "b"}, Claims{SignerDID: "did:x", Audience: viewAudience, Nonce: "n1", IssuedAt: sub})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if proof.IssuedAt.Nanosecond() != 0 {
		t.Errorf("proof issuedAt not truncated: %v", proof.IssuedAt)
	}
	// The signed bytes must use the truncated second, matching what a verifier
	// (which rejects sub-second input) will rebuild.
	want, _ := viewBytes(ViewVersion, "did:x", viewAudience, "Op", "n1", fixedTime(), map[string]any{"a": "b"})
	if !bytes.Equal(cs.data, want) {
		t.Errorf("Sign did not sign the truncated-second view:\n got=%s\nwant=%s", cs.data, want)
	}
}

func TestSign_RejectsEmptyParts(t *testing.T) {
	cs := &capturingSigner{}
	fields := map[string]any{"a": "b"}
	cases := map[string]struct{ did, audience, op, nonce string }{
		"empty signerDID": {"", viewAudience, "Op", "n1"},
		"empty audience":  {"did:x", "", "Op", "n1"},
		"empty op":        {"did:x", viewAudience, "", "n1"},
		"empty nonce":     {"did:x", viewAudience, "Op", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(cs, c.op, fields, Claims{SignerDID: c.did, Audience: c.audience, Nonce: c.nonce, IssuedAt: fixedTime()}); err == nil {
				t.Errorf("%s: want error, got nil", name)
			}
		})
	}
}

// Sign must mirror the verifier's nonce bound: a proof it mints for an oversized
// nonce would be structurally unverifiable, so Sign rejects it up front.
func TestSign_RejectsOversizedNonce(t *testing.T) {
	cs := &capturingSigner{}
	oversized := string(make([]byte, maxNonceLen+1))
	if _, err := Sign(cs, "Op", map[string]any{"a": "b"}, Claims{SignerDID: "did:x", Audience: viewAudience, Nonce: oversized, IssuedAt: fixedTime()}); !errors.Is(err, ErrMalformedProof) {
		t.Errorf("oversized nonce: want ErrMalformedProof, got %v", err)
	}
}

func TestNewNonce_UniqueAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if n == "" {
			t.Fatal("empty nonce")
		}
		if seen[n] {
			t.Fatalf("duplicate nonce %q", n)
		}
		seen[n] = true
	}
}
