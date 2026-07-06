package vc_test

import (
	"context"
	"strings"
	"testing"

	"github.com/provin-line/oss/vc"
)

func TestIsContentAddress(t *testing.T) {
	valid := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical form", valid, true},
		{"all digits", "sha256:" + strings.Repeat("12", 32), true},
		{"empty", "", false},
		{"prefix only", "sha256:", false},
		{"wrong prefix", "sha512:" + strings.Repeat("ab", 32), false},
		{"missing prefix", strings.Repeat("ab", 32), false},
		{"uppercase hex", "sha256:" + strings.Repeat("AB", 32), false},
		{"too short", "sha256:" + strings.Repeat("ab", 31), false},
		{"too long", "sha256:" + strings.Repeat("ab", 32) + "a", false},
		{"non-hex", "sha256:" + strings.Repeat("zz", 32), false},
		{"multihash form is a different encoding", "f1220" + strings.Repeat("ab", 32), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vc.IsContentAddress(tc.in); got != tc.want {
				t.Errorf("IsContentAddress(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// A nil receiver is a contract-violating call on a public method: it must
// return an error, never panic (Verify guards its own nil, a standalone
// caller has no such shield).
func TestValidateWireForm_NilReceiver_Errors(t *testing.T) {
	var c *vc.PipelinePassCredential
	if err := c.ValidateWireForm(); err == nil {
		t.Error("ValidateWireForm on a nil credential: want error")
	}
}

// ValidateWireForm is the receiver-side wire-form contract as one named
// operation: a built, well-formed credential passes; each malformation the
// data-integrity axis rejects is an error here. evalDataIntegrity delegates
// to it, so the two can never drift.
func TestValidateWireForm_WellFormedCredential(t *testing.T) {
	cred, _ := signedCred(t)
	if err := cred.ValidateWireForm(); err != nil {
		t.Errorf("ValidateWireForm on a builder-produced credential: %v", err)
	}
}

func TestValidateWireForm_ContentAddressFormats(t *testing.T) {
	bad := "not-a-sha256-hash!!"
	cases := []struct {
		name   string
		mutate func(subj map[string]any)
	}{
		{"malformed inputHash", func(s map[string]any) { s["inputHash"] = bad }},
		{"malformed outputHash", func(s map[string]any) { s["outputHash"] = bad }},
		{"malformed previousCredential", func(s map[string]any) { s["previousCredential"] = "sha256:short" }},
		{"uppercase-hex inputHash", func(s map[string]any) { s["inputHash"] = "sha256:" + strings.Repeat("AB", 32) }},
		// The typed subject view collapses these to "" — they must reject as
		// malformed, never skip as absent (only previousCredential has a
		// null-equals-omission reading).
		{"null inputHash", func(s map[string]any) { s["inputHash"] = nil }},
		{"non-string inputHash", func(s map[string]any) { s["inputHash"] = 123 }},
		{"empty-string inputHash", func(s map[string]any) { s["inputHash"] = "" }},
		{"non-string outputHash", func(s map[string]any) { s["outputHash"] = 123 }},
		{"empty-string previousCredential", func(s map[string]any) { s["previousCredential"] = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, _ := signedCred(t)
			forged := reUnmarshal(t, cred, func(m map[string]any) {
				tc.mutate(m["credentialSubject"].(map[string]any))
			})
			if err := forged.ValidateWireForm(); err == nil {
				t.Error("ValidateWireForm accepted a malformed content address")
			}
		})
	}
}

func TestValidateWireForm_ValidFromUTCSecondPrecision(t *testing.T) {
	// credential.field.valid-from: when present, validFrom MUST be an RFC 3339
	// UTC timestamp at second precision — a zoned offset or sub-second digits
	// reject as malformed even though time.Parse would accept them.
	cases := []struct {
		name      string
		validFrom any
		wantErr   bool
	}{
		{"UTC Z at second precision", "2026-06-10T00:00:00Z", false},
		{"zero numeric offset denotes UTC", "2026-06-10T00:00:00+00:00", false},
		{"non-UTC offset", "2026-06-10T09:00:00+09:00", true},
		// RFC 3339 §4.3: "-00:00" asserts the local offset is UNKNOWN — it is
		// not an assertion of UTC, so the profile rejects it (cred-032). Go's
		// parser folds it to offset 0, indistinguishable from Z/+00:00 after
		// parse, hence the string-level check in ValidateWireForm.
		{"unknown-local-offset -00:00", "2026-06-10T00:00:00-00:00", true},
		{"sub-second precision", "2026-06-10T00:00:00.500Z", true},
		{"sub-second zeros still reject", "2026-06-10T00:00:00.000Z", true},
		// Go's parser accepts a comma fraction separator (ISO 8601 leniency)
		// even though RFC 3339's ABNF only permits '.' — reject it too.
		{"comma sub-second precision", "2026-06-10T00:00:00,500Z", true},
		{"not RFC 3339", "2026/06/10 00:00:00", true},
		{"non-string", 20260610, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, _ := signedCred(t)
			forged := reUnmarshal(t, cred, func(m map[string]any) {
				m["validFrom"] = tc.validFrom
			})
			err := forged.ValidateWireForm()
			if tc.wantErr && err == nil {
				t.Error("ValidateWireForm accepted a non-UTC or sub-second validFrom")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateWireForm rejected a conformant validFrom: %v", err)
			}
		})
	}
}

// The cred-014 class end to end (review fix B-3, previously reproduced as
// DataIntegrity=Verified): a present-but-malformed content address fails the
// data-integrity axis.
func TestVerify_MalformedInputHash_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["credentialSubject"].(map[string]any)["inputHash"] = "not-a-sha256-hash!!"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (malformed inputHash format)", res.Axes.DataIntegrity)
	}
}

// 17f D-17f-6 leftover: a malformed previousCredential is rejected by the
// VERIFIER's wire-form check, not only by store ingress fail-closed drops.
func TestVerify_MalformedPreviousCredential_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["credentialSubject"].(map[string]any)["previousCredential"] = "sha256:nothex"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (malformed previousCredential format)", res.Axes.DataIntegrity)
	}
}

// Absent inputHash stays acceptable at single-credential level (presence on
// chain-preserving credentials is the chain check's concern — the spec's
// chain.data-flow.continuity; origins may legitimately omit it).
func TestVerify_AbsentInputHash_DataIntegrityVerified(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		delete(m["credentialSubject"].(map[string]any), "inputHash")
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceVerified {
		t.Errorf("DataIntegrity=%v, want Verified (absent inputHash is not a wire-form defect)", res.Axes.DataIntegrity)
	}
}
