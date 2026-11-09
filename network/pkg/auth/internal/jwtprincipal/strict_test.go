package jwtprincipal

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// rawHSToken signs payload as given, so a test can carry bytes a claims
// encoder would not write.
func rawHSToken(t *testing.T, payload string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: testSecret}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sig.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// claimsWith is a valid claims set with sub as given (a JSON string literal)
// and extra members appended.
func claimsWith(now time.Time, sub, extra string) string {
	return fmt.Sprintf(`{"iss":%q,"aud":%q,"exp":%d,"sub":%s%s}`, testIssuer, testAudience, now.Add(time.Hour).Unix(), sub, extra)
}

// The claims are read under canon.StrictDecoder's rules once the signature
// verifies: a subject (or any claim) whose bytes are not valid Unicode, a
// repeated key at any depth, and two keys of one object that differ only in
// case are refused, so two different sub values are not read as one.
func TestPrincipal_RefusesClaimsNotReadStrictly(t *testing.T) {
	now := time.Now()
	r := newHS(t, now)
	if got, err := r.Principal(context.Background(), rawHSToken(t, claimsWith(now, `"did:dplaax:alice"`, ""))); err != nil || got != "did:dplaax:alice" {
		t.Fatalf("valid claims: %q, %v", got, err)
	}
	for name, payload := range map[string]string{
		"invalid UTF-8 in sub":      claimsWith(now, "\"did:dplaax:al\xffice\"", ""),
		"unpaired surrogate in sub": claimsWith(now, `"did:dplaax:al\ud800ice"`, ""),
		"invalid UTF-8 elsewhere":   claimsWith(now, `"did:dplaax:alice"`, ",\"name\":\"\xff\""),
		"a repeated sub":            claimsWith(now, `"did:dplaax:alice"`, `,"sub":"did:dplaax:bob"`),
		"a repeated nested key":     claimsWith(now, `"did:dplaax:alice"`, `,"realm_access":{"roles":["a"],"roles":["b"]}`),
		"keys only in another case": claimsWith(now, `"did:dplaax:alice"`, `,"Name":"a","name":"b"`),
	} {
		if got, err := r.Principal(context.Background(), rawHSToken(t, payload)); err == nil {
			t.Errorf("%s: accepted, principal %q", name, got)
		}
	}
}

// A token is a compact JWS in its one spelling: three base64url segments
// without padding, each with the unused bits of its last character zero. A
// line break, which base64 decoding skips, or nonzero unused bits, which it
// ignores, is refused, so one signed token has one spelling.
func TestPrincipal_RefusesATokenNotInCompactForm(t *testing.T) {
	now := time.Now()
	r := newHS(t, now)
	tok := hsToken(t, testSecret, validClaims(now))
	if _, err := r.Principal(context.Background(), tok); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	h, rest, _ := strings.Cut(tok, ".")
	p, s, _ := strings.Cut(rest, ".")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// unusedBit sets the lowest unused bit of seg's last character, a
	// spelling base64 decoding reads as the same bytes.
	unusedBit := func(seg string) string {
		if len(seg)%4 == 0 {
			t.Fatalf("segment %q has no unused bits", seg)
		}
		return seg[:len(seg)-1] + string(alphabet[strings.IndexByte(alphabet, seg[len(seg)-1])+1])
	}
	for name, bad := range map[string]string{
		"unused bits in the signature": h + "." + p + "." + unusedBit(s),
		"CR LF in the header":          h[:4] + "\r\n" + h[4:] + "." + p + "." + s,
		"a line break in the payload":  h + "." + p[:4] + "\n" + p[4:] + "." + s,
		"CR LF in the signature":       h + "." + p + "." + s[:4] + "\r\n" + s[4:],
		"a space":                      h + "." + p + " ." + s,
		"padding":                      h + "." + p + "." + s + "=",
		"standard base64 characters":   h + "." + p + "." + strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/") + "+",
		"an empty signature":           h + "." + p + ".",
		"four segments":                h + "." + p + "." + s + ".x",
	} {
		if got, err := r.Principal(context.Background(), bad); err == nil {
			t.Errorf("%s: accepted, principal %q", name, got)
		}
	}
}
