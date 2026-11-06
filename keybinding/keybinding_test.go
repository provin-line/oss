package keybinding_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	ossed "github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keybinding"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const (
	issuerDID = "did:dplaax:poc.dplaax.dev:org:acme"
	otherDID  = "did:dplaax:poc.dplaax.dev:org:other"
	audience  = "did:dplaax:poc.dplaax.dev:org:bank"
	listID    = issuerDID + "#key-binding-status-list"
)

var t0 = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

// keys signs as DID#fragment with the keys it holds.
type keys map[string]stded25519.PrivateKey

func (k keys) Sign(didStr, keyID string, data []byte) ([]byte, error) {
	priv, ok := k[didStr+"#"+keyID]
	if !ok {
		return nil, fmt.Errorf("no key %s#%s", didStr, keyID)
	}
	return stded25519.Sign(priv, data), nil
}

type fixture struct {
	signer keys
	v      *keybinding.Verifier
	anchor keybinding.Anchor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	k := keys{}
	r := local.New()
	for _, d := range []string{issuerDID, otherDID} {
		var vms []did.VerificationMethod
		var refs []string
		for _, frag := range []string{"issuer", "signing"} {
			pub, priv, err := stded25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			k[d+"#"+frag] = priv
			vm, err := did.NewMultikeyVerificationMethod(d+"#"+frag, d, pub)
			if err != nil {
				t.Fatal(err)
			}
			vms = append(vms, vm)
			refs = append(refs, d+"#"+frag)
		}
		r.Add(did.New(did.DocumentFields{Context: did.IssuedDocumentContexts(), ID: d, Controller: d, VerificationMethod: vms, AssertionMethod: refs}))
	}
	v, err := keybinding.NewVerifier(vc.NewVerifier(r, ossed.Verifier{}), audience, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{signer: k, v: v, anchor: keybinding.Anchor{
		Issuer: issuerDID, IssuanceKeys: []string{issuerDID + "#issuer"},
		MaxValidity: 48 * time.Hour, MaxStatusAge: 2 * time.Hour,
	}}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecKey is a P-256 key as a JWK.
var ecKey = func() map[string]any {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pt, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(pt[1:33]), "y": b64(pt[33:])}
}()

func sampleBinding() keybinding.Binding {
	jwk := map[string]any{}
	for k, v := range ecKey {
		jwk[k] = v
	}
	return keybinding.Binding{
		Issuer: issuerDID, Subject: "urn:acme:staff:42", Kind: "staff", Roles: []string{"checker"},
		Audience: audience, KeyClass: "passkey",
		Key:       keybinding.Key{ID: "credential-1", PublicKeyJWK: jwk},
		ValidFrom: t0, ValidUntil: t0.Add(24 * time.Hour),
		Status: keybinding.StatusEntry{List: listID, Index: 7},
	}
}

func (f *fixture) list(t *testing.T, issuer, fragment string, from time.Time, revoked ...uint64) []byte {
	t.Helper()
	raw, err := keybinding.IssueStatusList(f.signer, issuer, fragment, issuer+"#key-binding-status-list", from, from.Add(time.Hour), revoked, keybinding.MinStatusListSize)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) heldList(t *testing.T, at time.Time, revoked ...uint64) *keybinding.StatusList {
	t.Helper()
	l, err := f.v.VerifyStatusList(context.Background(), f.list(t, issuerDID, "issuer", at.Add(-time.Minute), revoked...), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mutate(t *testing.T, raw []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIssueAndVerify(t *testing.T) {
	f := newFixture(t)
	at := t0.Add(time.Hour)
	raw, err := keybinding.Issue(f.signer, issuerDID, "issuer", sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.v.VerifyBinding(context.Background(), raw, f.anchor, f.heldList(t, at), at)
	if err != nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	if !reflect.DeepEqual(got, sampleBinding()) {
		t.Errorf("binding = %+v, want %+v", got, sampleBinding())
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if idx := m["credentialStatus"].(map[string]any)["statusListIndex"]; idx != "7" {
		t.Errorf("statusListIndex = %#v, want the string \"7\"", idx)
	}
}

func TestVerifyBinding_Refusals(t *testing.T) {
	f := newFixture(t)
	at := t0.Add(time.Hour)
	held := f.heldList(t, at)
	good, err := keybinding.Issue(f.signer, issuerDID, "issuer", sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	issueWith := func(edit func(b *keybinding.Binding)) []byte {
		b := sampleBinding()
		edit(&b)
		raw, err := keybinding.Issue(f.signer, issuerDID, "issuer", b)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	signedBy := func(issuer, fragment string) []byte {
		b := sampleBinding()
		b.Issuer = issuer
		raw, err := keybinding.Issue(f.signer, issuer, fragment, b)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	subject := func(m map[string]any) map[string]any { return m["credentialSubject"].(map[string]any) }
	for _, tc := range []struct {
		name string
		raw  []byte
		at   time.Time
		list *keybinding.StatusList
		want error
	}{
		{"tampered", mutate(t, good, func(m map[string]any) { subject(m)["kind"] = "customer" }), at, held, keybinding.ErrSignature},
		{"a key that is not for issuing", signedBy(issuerDID, "signing"), at, held, keybinding.ErrSignature},
		{"another issuer", signedBy(otherDID, "issuer"), at, held, keybinding.ErrSignature},
		{"before validFrom", good, t0.Add(-2 * time.Minute), held, keybinding.ErrNotValidAt},
		{"at validUntil", good, t0.Add(24*time.Hour + time.Minute), f.heldList(t, t0.Add(24*time.Hour+time.Minute)), keybinding.ErrNotValidAt},
		{"too long", issueWith(func(b *keybinding.Binding) { b.ValidUntil = t0.Add(72 * time.Hour) }), at, held, keybinding.ErrValidityTooLong},
		{"another audience", issueWith(func(b *keybinding.Binding) { b.Audience = otherDID }), at, held, keybinding.ErrAudience},
		{"revoked", good, at, f.heldList(t, at, 7), keybinding.ErrRevoked},
		{"no status list", good, at, nil, keybinding.ErrStatusListStale},
		{"a stale status list", good, at.Add(3 * time.Hour), held, keybinding.ErrStatusListStale},
		{"an index past the list", issueWith(func(b *keybinding.Binding) { b.Status.Index = keybinding.MinStatusListSize }), at, held, keybinding.ErrMalformed},
		{"another list", issueWith(func(b *keybinding.Binding) { b.Status.List = issuerDID + "#another-list" }), at, held, keybinding.ErrStatusListStale},
		{"no time", good, time.Time{}, held, keybinding.ErrNotValidAt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.v.VerifyBinding(context.Background(), tc.raw, f.anchor, tc.list, tc.at)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A binding is read in one shape: required members present, strings where
// strings are, roles always a list, the JWK in its required members only, no
// numbers.
func TestVerifyBinding_RefusesOtherShapes(t *testing.T) {
	f := newFixture(t)
	for name, edit := range map[string]func(b map[string]any){
		"roles missing":           func(b map[string]any) { delete(b["credentialSubject"].(map[string]any), "roles") },
		"roles not a list":        func(b map[string]any) { b["credentialSubject"].(map[string]any)["roles"] = "checker" },
		"a role not a string":     func(b map[string]any) { b["credentialSubject"].(map[string]any)["roles"] = []any{1} },
		"no keyClass":             func(b map[string]any) { delete(b["credentialSubject"].(map[string]any), "keyClass") },
		"an extra JWK member":     func(b map[string]any) { jwk(b)["kid"] = "x" },
		"a JWK value padded":      func(b map[string]any) { jwk(b)["x"] = jwk(b)["x"].(string) + "=" },
		"an unknown kty":          func(b map[string]any) { jwk(b)["kty"] = "oct" },
		"a number index":          func(b map[string]any) { b["credentialStatus"].(map[string]any)["statusListIndex"] = 7 },
		"a signed index":          func(b map[string]any) { b["credentialStatus"].(map[string]any)["statusListIndex"] = "+7" },
		"a leading zero":          func(b map[string]any) { b["credentialStatus"].(map[string]any)["statusListIndex"] = "07" },
		"another status type":     func(b map[string]any) { b["credentialStatus"].(map[string]any)["type"] = "StatusList2021Entry" },
		"a suspension entry":      func(b map[string]any) { b["credentialStatus"].(map[string]any)["statusPurpose"] = "suspension" },
		"not a key binding":       func(b map[string]any) { b["type"] = []any{"VerifiableCredential"} },
		"no VerifiableCredential": func(b map[string]any) { b["type"] = []any{"KeyBindingCredential"} },
		"another context":         func(b map[string]any) { b["@context"] = []any{"https://www.w3.org/ns/credentials/v2"} },
		"a statusSize":            func(b map[string]any) { b["credentialStatus"].(map[string]any)["statusSize"] = "2" },
		"an empty role":           func(b map[string]any) { b["credentialSubject"].(map[string]any)["roles"] = []any{""} },
		"a repeated role":         func(b map[string]any) { b["credentialSubject"].(map[string]any)["roles"] = []any{"checker", "checker"} },
		"key.id, not keyId": func(b map[string]any) {
			k := b["credentialSubject"].(map[string]any)["key"].(map[string]any)
			k["id"] = k["keyId"]
			delete(k, "keyId")
		},
		"a curve not P-256":     func(b map[string]any) { jwk(b)["crv"] = "P-384" },
		"a point off P-256":     func(b map[string]any) { jwk(b)["y"] = b64(bytes.Repeat([]byte{2}, 32)) },
		"a short coordinate":    func(b map[string]any) { jwk(b)["x"] = b64([]byte{1, 2, 3}) },
		"validFrom with millis": func(b map[string]any) { b["validFrom"] = "2026-11-06T00:00:00.000Z" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := keybinding.IssueBody(f.signer, issuerDID, "issuer", sampleBinding(), edit)
			if err != nil {
				t.Fatal(err)
			}
			at := t0.Add(time.Hour)
			if _, err := f.v.VerifyBinding(context.Background(), raw, f.anchor, f.heldList(t, at), at); !errors.Is(err, keybinding.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func jwk(b map[string]any) map[string]any {
	return b["credentialSubject"].(map[string]any)["key"].(map[string]any)["publicKeyJwk"].(map[string]any)
}

func TestIssue_RefusesWhatCannotBeRead(t *testing.T) {
	f := newFixture(t)
	for name, edit := range map[string]func(b *keybinding.Binding){
		"no subject":        func(b *keybinding.Binding) { b.Subject = "" },
		"no audience":       func(b *keybinding.Binding) { b.Audience = "" },
		"no key id":         func(b *keybinding.Binding) { b.Key.ID = "" },
		"an extra JWK key":  func(b *keybinding.Binding) { b.Key.PublicKeyJWK["kid"] = "x" },
		"until before from": func(b *keybinding.Binding) { b.ValidUntil = b.ValidFrom },
		"fraction seconds":  func(b *keybinding.Binding) { b.ValidFrom = b.ValidFrom.Add(time.Millisecond) },
		"another issuer":    func(b *keybinding.Binding) { b.Issuer = otherDID },
	} {
		b := sampleBinding()
		edit(&b)
		if _, err := keybinding.Issue(f.signer, issuerDID, "issuer", b); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
}

func TestStatusList(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	first := f.list(t, issuerDID, "issuer", at.Add(-30*time.Minute), 3, 131071)
	held, err := f.v.VerifyStatusList(ctx, first, f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	for idx, want := range map[uint64]bool{0: false, 3: true, 4: false, 131071: true} {
		got, err := held.Revoked(idx)
		if err != nil || got != want {
			t.Errorf("Revoked(%d) = %v, %v; want %v", idx, got, err, want)
		}
	}
	if _, err := held.Revoked(keybinding.MinStatusListSize); err == nil {
		t.Error("Revoked past the end: no error")
	}

	// The same list again is the held list; an earlier one, or another one with
	// the same validFrom, is a rewind; a later one that keeps its marks
	// replaces it.
	if again, err := f.v.VerifyStatusList(ctx, first, f.anchor, held, at); err != nil || again != held {
		t.Errorf("the same list again = %v, %v; want the held list", again, err)
	}
	for name, raw := range map[string][]byte{
		"earlier":                 f.list(t, issuerDID, "issuer", at.Add(-40*time.Minute)),
		"same validFrom, changed": f.list(t, issuerDID, "issuer", at.Add(-30*time.Minute), 3),
	} {
		if _, err := f.v.VerifyStatusList(ctx, raw, f.anchor, held, at); !errors.Is(err, keybinding.ErrStatusListRewound) {
			t.Errorf("%s: err = %v, want ErrStatusListRewound", name, err)
		}
	}
	later, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", at.Add(-10*time.Minute), 3, 131071), f.anchor, held, at)
	if err != nil || later == held {
		t.Fatalf("a later list: %v, %v", later, err)
	}

	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"signed with a key not for issuing": {f.list(t, issuerDID, "signing", at.Add(-time.Minute)), keybinding.ErrSignature},
		"of another issuer":                 {f.list(t, otherDID, "issuer", at.Add(-time.Minute)), keybinding.ErrSignature},
		"tampered":                          {mutate(t, first, func(m map[string]any) { m["validUntil"] = "2027-01-01T00:00:00Z" }), keybinding.ErrSignature},
		"stale":                             {f.list(t, issuerDID, "issuer", at.Add(-3*time.Hour)), keybinding.ErrStatusListStale},
	} {
		if _, err := f.v.VerifyStatusList(ctx, tc.raw, f.anchor, nil, at); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

// A revocation cannot be undone (W3C Bitstring Status List, statusPurpose
// revocation): a later list that clears a mark the held list has — dropped,
// or past the end of a shorter list — is refused, not a rewind, so an issuer
// restored to an older state cannot undo a revocation a relying party has
// seen. A shorter list that keeps every mark is taken.
func TestStatusList_RefusesALaterListThatClearsARevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	from, later := at.Add(-30*time.Minute), at.Add(-10*time.Minute)
	held, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", from, 3, 131071), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	cleared := f.list(t, issuerDID, "issuer", later, 3)
	_, err = f.v.VerifyStatusList(ctx, cleared, f.anchor, held, at)
	if !errors.Is(err, keybinding.ErrStatusListRevocationCleared) || errors.Is(err, keybinding.ErrStatusListRewound) || !strings.HasSuffix(err.Error(), ": entry 131071") {
		t.Errorf("a later list without mark 131071: err = %v, want ErrStatusListRevocationCleared at entry 131071", err)
	}

	big := 2 * uint64(keybinding.MinStatusListSize)
	issue := func(from time.Time, size uint64, revoked ...uint64) []byte {
		t.Helper()
		raw, err := keybinding.IssueStatusList(f.signer, issuerDID, "issuer", listID, from, from.Add(time.Hour), revoked, size)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	heldBig, err := f.v.VerifyStatusList(ctx, issue(from, big, 3, big-1), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(ctx, issue(later, keybinding.MinStatusListSize, 3), f.anchor, heldBig, at); !errors.Is(err, keybinding.ErrStatusListRevocationCleared) || !strings.HasSuffix(err.Error(), fmt.Sprintf(": entry %d", big-1)) {
		t.Errorf("a shorter list that loses mark %d: err = %v, want ErrStatusListRevocationCleared at entry %d", big-1, err, big-1)
	}
	heldBig, err = f.v.VerifyStatusList(ctx, issue(from, big, 3), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	if shorter, err := f.v.VerifyStatusList(ctx, issue(later, keybinding.MinStatusListSize, 3), f.anchor, heldBig, at); err != nil || shorter == heldBig {
		t.Errorf("a shorter list that keeps every mark = %v, %v; want the new list", shorter, err)
	}
}

// A later list may add revocations: it is taken and replaces the held list.
func TestStatusList_TakesALaterListThatAddsARevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	held, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", at.Add(-30*time.Minute), 3), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	later, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", at.Add(-10*time.Minute), 3, 4), f.anchor, held, at)
	if err != nil || later == held {
		t.Fatalf("a later list with mark 4 added: %v, %v", later, err)
	}
	for idx, want := range map[uint64]bool{3: true, 4: true, 5: false} {
		if got, err := later.Revoked(idx); err != nil || got != want {
			t.Errorf("Revoked(%d) = %v, %v; want %v", idx, got, err, want)
		}
	}
}

// An encoded list that expands past the limit is refused, not expanded.
func TestStatusList_RefusesAnOversizedExpansion(t *testing.T) {
	f := newFixture(t)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(make([]byte, keybinding.MaxStatusListBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := keybinding.IssueStatusListEncoded(f.signer, issuerDID, "issuer", listID, t0, t0.Add(time.Hour), "u"+b64(gz.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(context.Background(), raw, f.anchor, nil, t0.Add(time.Minute)); !errors.Is(err, keybinding.ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestNewVerifier_RefusesMissingParts(t *testing.T) {
	if _, err := keybinding.NewVerifier(nil, audience, time.Minute); err == nil {
		t.Error("no vc.Verifier: accepted")
	}
	if _, err := keybinding.NewVerifier(vc.NewVerifier(local.New(), ossed.Verifier{}), "", time.Minute); err == nil {
		t.Error("no audience: accepted")
	}
	if _, err := keybinding.NewVerifier(vc.NewVerifier(local.New(), ossed.Verifier{}), audience, -time.Second); err == nil {
		t.Error("negative skew: accepted")
	}
}

// The status list is current only from its validFrom: a list dated in the
// future is refused, does not become held, and so cannot block the real
// lists that follow.
func TestStatusList_RefusesAListNotYetValid(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	future := f.list(t, issuerDID, "issuer", at.Add(30*24*time.Hour))
	if _, err := f.v.VerifyStatusList(ctx, future, f.anchor, nil, at); !errors.Is(err, keybinding.ErrStatusListStale) {
		t.Errorf("a future-dated list: err = %v, want ErrStatusListStale", err)
	}
	if _, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", at.Add(-time.Minute)), f.anchor, nil, time.Time{}); !errors.Is(err, keybinding.ErrStatusListStale) {
		t.Errorf("no time: err = %v, want ErrStatusListStale", err)
	}
}

// A list held and fetched again is current only while it is: the same list
// later than its freshness is refused, not returned.
func TestStatusList_TheSameListAgainIsCheckedAgain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	raw := f.list(t, issuerDID, "issuer", at.Add(-time.Minute))
	held, err := f.v.VerifyStatusList(ctx, raw, f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(ctx, raw, f.anchor, held, at.Add(5*time.Hour)); !errors.Is(err, keybinding.ErrStatusListStale) {
		t.Errorf("the same list 5 hours later: err = %v, want ErrStatusListStale", err)
	}
}

// A list is its issuer's alone: its id is a DID URL of the issuer, a held list
// of another issuer is refused, and the same validFrom with another body
// (here, another validUntil) is a rewind.
func TestStatusList_IsTheIssuers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := t0.Add(time.Hour)
	from := at.Add(-time.Minute)
	foreignID, err := keybinding.IssueStatusList(f.signer, issuerDID, "issuer", otherDID+"#key-binding-status-list", from, from.Add(time.Hour), nil, keybinding.MinStatusListSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(ctx, foreignID, f.anchor, nil, at); !errors.Is(err, keybinding.ErrMalformed) {
		t.Errorf("a list id of another DID: err = %v, want ErrMalformed", err)
	}
	for _, id := range []string{issuerDID + "#bad fragment", issuerDID + "#a#b", issuerDID + "#sign%69ng", issuerDID + "#"} {
		raw, err := keybinding.IssueStatusList(f.signer, issuerDID, "issuer", id, from, from.Add(time.Hour), nil, keybinding.MinStatusListSize)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.v.VerifyStatusList(ctx, raw, f.anchor, nil, at); !errors.Is(err, keybinding.ErrMalformed) {
			t.Errorf("list id %q: err = %v, want ErrMalformed", id, err)
		}
	}
	held, err := f.v.VerifyStatusList(ctx, f.list(t, issuerDID, "issuer", from), f.anchor, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	longer, err := keybinding.IssueStatusList(f.signer, issuerDID, "issuer", listID, from, from.Add(90*time.Minute), nil, keybinding.MinStatusListSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(ctx, longer, f.anchor, held, at); !errors.Is(err, keybinding.ErrStatusListRewound) {
		t.Errorf("same validFrom, another validUntil: err = %v, want ErrStatusListRewound", err)
	}
	otherAnchor := keybinding.Anchor{Issuer: otherDID, IssuanceKeys: []string{otherDID + "#issuer"}, MaxValidity: time.Hour, MaxStatusAge: time.Hour}
	if _, err := f.v.VerifyStatusList(ctx, f.list(t, otherDID, "issuer", from), otherAnchor, held, at); !errors.Is(err, keybinding.ErrMalformed) {
		t.Errorf("a held list of another issuer: err = %v, want ErrMalformed", err)
	}
	// The held list's signing key leaves the anchor: the list no longer
	// counts, even for a binding signed with a key that is still in it.
	rotated := f.anchor
	rotated.IssuanceKeys = []string{issuerDID + "#signing"}
	raw, err := keybinding.Issue(f.signer, issuerDID, "signing", sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyBinding(ctx, raw, rotated, held, at); !errors.Is(err, keybinding.ErrStatusListStale) {
		t.Errorf("after the list's key left the anchor: err = %v, want ErrStatusListStale", err)
	}
}

func TestStatusList_RefusesAnotherSpellingOfTheList(t *testing.T) {
	f := newFixture(t)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(make([]byte, keybinding.MinStatusListSize/8)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	enc := b64(gz.Bytes())
	raw, err := keybinding.IssueStatusListEncoded(f.signer, issuerDID, "issuer", listID, t0, t0.Add(time.Hour), "u"+enc[:10]+"\n"+enc[10:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.VerifyStatusList(context.Background(), raw, f.anchor, nil, t0.Add(time.Minute)); !errors.Is(err, keybinding.ErrMalformed) {
		t.Errorf("an encodedList with a line break: err = %v, want ErrMalformed", err)
	}
}

// outage fails every resolution with a transient error.
type outage struct{}

func (outage) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// An issuer's document that cannot be read now is not a forgery.
func TestVerify_AnUnavailableIssuerIsNotAForgery(t *testing.T) {
	f := newFixture(t)
	v, err := keybinding.NewVerifier(vc.NewVerifier(outage{}, ossed.Verifier{}), audience, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keybinding.Issue(f.signer, issuerDID, "issuer", sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	at := t0.Add(time.Hour)
	if _, err := v.VerifyBinding(context.Background(), raw, f.anchor, f.heldList(t, at), at); !errors.Is(err, keybinding.ErrSignatureUnestablished) {
		t.Errorf("err = %v, want ErrSignatureUnestablished", err)
	}
}

// Zero values fail closed.
func TestZeroValues(t *testing.T) {
	var v keybinding.Verifier
	if _, err := v.VerifyBinding(context.Background(), nil, keybinding.Anchor{}, nil, t0); err == nil {
		t.Error("a zero Verifier verified a binding")
	}
	if _, err := v.VerifyStatusList(context.Background(), nil, keybinding.Anchor{}, nil, t0); err == nil {
		t.Error("a zero Verifier verified a list")
	}
	var l *keybinding.StatusList
	if _, err := l.Revoked(0); err == nil {
		t.Error("a nil list answered")
	}
}

// Ed25519 and RSA keys bind in their one spelling; a key that is not usable
// does not.
func TestJWKKinds(t *testing.T) {
	f := newFixture(t)
	edPub, _, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(rsaKey.E)).Bytes()
	for name, tc := range map[string]struct {
		jwk map[string]any
		ok  bool
	}{
		"Ed25519":           {map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(edPub)}, true},
		"RSA 2048":          {map[string]any{"kty": "RSA", "n": b64(rsaKey.N.Bytes()), "e": b64(e)}, true},
		"X25519":            {map[string]any{"kty": "OKP", "crv": "X25519", "x": b64(edPub)}, false},
		"a small-order OKP": {map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(append([]byte{1}, make([]byte, 31)...))}, false},
		"RSA with a zero":   {map[string]any{"kty": "RSA", "n": b64(append([]byte{0}, rsaKey.N.Bytes()...)), "e": b64(e)}, false},
		"RSA of 16 bits":    {map[string]any{"kty": "RSA", "n": b64([]byte{0xc3, 0x51}), "e": b64(e)}, false},
	} {
		b := sampleBinding()
		b.Key.PublicKeyJWK = tc.jwk
		_, err := keybinding.Issue(f.signer, issuerDID, "issuer", b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Issue err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}
