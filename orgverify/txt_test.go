package orgverify

import (
	"strings"
	"testing"
)

func TestParseTXT_Valid(t *testing.T) {
	raw := "v=dplaax1; did=did:dplaax:registry.dplaax.dev:org:acme.com; key=sha256:3a7bd5cd6b8e8f6a4f1c5e0d9b8a7e6d5c4b3a2918273645546372819aebcdef"
	rec, err := ParseTXT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Version != "dplaax1" {
		t.Errorf("Version=%q, want dplaax1", rec.Version)
	}
	if rec.DID != "did:dplaax:registry.dplaax.dev:org:acme.com" {
		t.Errorf("DID=%q", rec.DID)
	}
	if rec.KeyFingerprint != "sha256:3a7bd5cd6b8e8f6a4f1c5e0d9b8a7e6d5c4b3a2918273645546372819aebcdef" {
		t.Errorf("KeyFingerprint=%q", rec.KeyFingerprint)
	}
	if rec.Raw != raw {
		t.Errorf("Raw not preserved")
	}
}

// Unknown keys are forward-compatible and ignored, including when they
// appear alongside all three known keys.
func TestParseTXT_UnknownKeyIgnored(t *testing.T) {
	raw := "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64) + "; future=whatever"
	rec, err := ParseTXT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Version != "dplaax1" || rec.DID != "did:dplaax:r:org:a" {
		t.Errorf("known fields not parsed: %+v", rec)
	}
}

func TestParseTXT_Invalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"missing v", "did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64)},
		{"missing did", "v=dplaax1; key=sha256:" + strings.Repeat("a", 64)},
		{"missing key", "v=dplaax1; did=did:dplaax:r:org:a"},
		{"wrong version", "v=dplaax2; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64)},
		{"key uppercase hex", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("A", 64)},
		{"key short", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:abcd"},
		{"key non-hex", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("g", 64)},
		{"key wrong prefix", "v=dplaax1; did=did:dplaax:r:org:a; key=sha512:" + strings.Repeat("a", 64)},
		{"key base64 not hex", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 43) + "="},
		{"empty", ""},
		{"junk", "this is not a txt record"},
		// spec §7.5: a segment with no "=" is malformed, not silently skipped.
		{"segment without equals", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64) + "; junk"},
		{"trailing semicolon leaves empty segment", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64) + ";"},
		// spec §7.5: a known key appearing twice is malformed, not last-wins.
		{"duplicate v=", "v=dplaax1; v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64)},
		{"duplicate did=", "v=dplaax1; did=did:dplaax:r:org:a; did=did:dplaax:r:org:b; key=sha256:" + strings.Repeat("a", 64)},
		{"duplicate key=", "v=dplaax1; did=did:dplaax:r:org:a; key=sha256:" + strings.Repeat("a", 64) + "; key=sha256:" + strings.Repeat("b", 64)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseTXT(c.input)
			if err == nil {
				t.Errorf("expected error for %q", c.input)
			}
		})
	}
}

func TestGenerateTXT(t *testing.T) {
	got, err := GenerateTXT("did:dplaax:registry.dplaax.dev:org:acme.com", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "v=dplaax1; did=did:dplaax:registry.dplaax.dev:org:acme.com; key=sha256:" + strings.Repeat("a", 64)
	if got != want {
		t.Errorf("GenerateTXT()=%q\nwant=%q", got, want)
	}
	parsed, err := ParseTXT(got)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if parsed.DID != "did:dplaax:registry.dplaax.dev:org:acme.com" {
		t.Errorf("round-trip DID mismatch")
	}
}

func TestGenerateTXT_RejectsInvalidFingerprint(t *testing.T) {
	_, err := GenerateTXT("did:dplaax:r:org:a", "sha256:ABC")
	if err == nil {
		t.Error("expected error for invalid fingerprint")
	}
}

func TestRecordName(t *testing.T) {
	if got, want := RecordName("acme.com"), "_dplaax-org.acme.com"; got != want {
		t.Errorf("RecordName()=%q, want %q", got, want)
	}
}
