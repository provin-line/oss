// Package keybinding is the key binding: a credential in which an issuer
// states that a key belongs to a subject — of a kind, with roles, of a key
// class — for one relying party, for a period, with an entry in the issuer's
// revocation list. A relying party verifies it against its trust anchor for the
// issuer and the issuer's revocation list it holds, without asking the issuer
// at decision time.
//
// The binding is a W3C Verifiable Credential of type KeyBindingCredential,
// signed with eddsa-jcs-2022 under the W3C contract; the revocation list is a
// W3C Bitstring Status List credential signed the same way. The wire holds no
// JSON numbers: the list index is a decimal string, so no two indexes share a
// canonical form.
//
// What an issuer may bind (the kinds, roles and key classes in its scope) is
// not evaluated here; Binding carries them for the caller's scope check.
package keybinding

import (
	"bytes"
	"compress/gzip"
	"context"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/crypto/es256"
	"github.com/provin-line/oss/crypto/rs256"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/vc"
)

// Error is the type of this package's constant sentinel errors: each names the
// check a binding or a status list failed.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrSignature Error = "keybinding: not signed by the issuer's issuance key"
	// ErrSignatureUnestablished: the signature could not be checked now (the
	// issuer's document or the cryptosuite lifecycle is unavailable); it may
	// verify later. Not a forgery.
	ErrSignatureUnestablished Error = "keybinding: the issuer's signature could not be established now"
	ErrMalformed              Error = "keybinding: malformed"
	ErrNotValidAt             Error = "keybinding: not valid at this time"
	ErrValidityTooLong        Error = "keybinding: valid for longer than the trust anchor allows"
	ErrRevoked                Error = "keybinding: revoked"
	ErrStatusListStale        Error = "keybinding: no current status list"
	ErrStatusListRewound      Error = "keybinding: status list older than the one held"
	// ErrStatusListRevocationCleared: a later list leaves unmarked an entry the
	// held list marks. A revocation is not reversible.
	ErrStatusListRevocationCleared Error = "keybinding: status list clears a revocation the one held marks"
	ErrAudience                    Error = "keybinding: for another relying party"
)

// Wire vocabulary.
const (
	TypeKeyBinding        = "KeyBindingCredential"
	TypeStatusList        = "BitstringStatusListCredential"
	statusEntryType       = "BitstringStatusListEntry"
	statusListSubjectType = "BitstringStatusList"
	statusPurpose         = "revocation"
)

// MinStatusListSize is the smallest status list, in entries (16 KB of bits,
// the W3C Bitstring Status List minimum, so an index says little about who
// holds it). MaxStatusListBytes bounds the expanded list a verifier accepts.
const (
	MinStatusListSize  = 131072
	MaxStatusListBytes = 16 << 20
)

// timeLayout is the one spelling of a time on the wire: UTC, to the second
// (credential.field.valid-from).
const timeLayout = "2006-01-02T15:04:05Z"

// Binding is what an issuer binds.
type Binding struct {
	Issuer     string   // the issuer's DID
	Subject    string   // the subject, in the issuer's namespace
	Kind       string   // the kind of subject (customer, staff, …), in the relying party's vocabulary
	Roles      []string // the subject's roles; none is an empty list
	Audience   string   // the relying party the binding is for (its organization DID)
	KeyClass   string   // the key class (passkey, session, …), in the relying party's vocabulary
	Key        Key
	ValidFrom  time.Time // to the second
	ValidUntil time.Time // to the second, after ValidFrom
	Status     StatusEntry
}

// Key is the bound key.
type Key struct {
	ID string // the key's id (wire: keyId), unique within the issuer (what a signature names)
	// PublicKeyJWK is an RFC 7517 public JWK in one spelling: exactly the
	// members RFC 7638 hashes for its kty, every value but kty and crv
	// canonical unpadded base64url; OKP is Ed25519 (a key
	// crypto/ed25519.ValidatePublicKey accepts), EC is P-256 (32-byte x and y,
	// a point crypto/es256 accepts), RSA has n and e without leading zero
	// octets (a key crypto/rs256 accepts).
	PublicKeyJWK map[string]any
}

// StatusEntry is the binding's place in the issuer's revocation list.
type StatusEntry struct {
	List  string // the status list credential's id
	Index uint64 // on the wire, a decimal string without leading zeros
}

// Issue signs b with the issuer's key issuer#keyFragment (eddsa-jcs-2022) and
// returns the credential. b.Issuer must be issuer.
func Issue(signer crypto.Signer, issuer, keyFragment string, b Binding) ([]byte, error) {
	return issueBody(signer, issuer, keyFragment, b, nil)
}

func issueBody(signer crypto.Signer, issuer, keyFragment string, b Binding, edit func(map[string]any)) ([]byte, error) {
	if b.Issuer != issuer {
		return nil, fmt.Errorf("keybinding: binding issuer %q is not %q", b.Issuer, issuer)
	}
	body, err := bindingBody(b)
	if err != nil {
		return nil, err
	}
	if edit != nil {
		edit(body)
	}
	return sign(signer, issuer, keyFragment, body)
}

func bindingBody(b Binding) (map[string]any, error) {
	switch {
	case b.Issuer == "", b.Subject == "", b.Kind == "", b.Audience == "", b.KeyClass == "", b.Key.ID == "", b.Status.List == "":
		return nil, errors.New("keybinding: a required field is empty")
	case !b.ValidUntil.After(b.ValidFrom):
		return nil, errors.New("keybinding: validUntil is not after validFrom")
	}
	from, err := formatTime(b.ValidFrom)
	if err != nil {
		return nil, err
	}
	until, err := formatTime(b.ValidUntil)
	if err != nil {
		return nil, err
	}
	if err := checkJWK(b.Key.PublicKeyJWK); err != nil {
		return nil, err
	}
	roles := make([]any, len(b.Roles))
	for i, r := range b.Roles {
		roles[i] = r
	}
	jwk := make(map[string]any, len(b.Key.PublicKeyJWK))
	for k, v := range b.Key.PublicKeyJWK {
		jwk[k] = v
	}
	return map[string]any{
		"@context":   []any{vc.ContextCredentialsV2, vc.ContextDplaaxVCV1},
		"type":       []any{"VerifiableCredential", TypeKeyBinding},
		"issuer":     b.Issuer,
		"validFrom":  from,
		"validUntil": until,
		"credentialStatus": map[string]any{
			"type":                 statusEntryType,
			"statusPurpose":        statusPurpose,
			"statusListIndex":      strconv.FormatUint(b.Status.Index, 10),
			"statusListCredential": b.Status.List,
		},
		"credentialSubject": map[string]any{
			"id":       b.Subject,
			"kind":     b.Kind,
			"roles":    roles,
			"audience": b.Audience,
			"keyClass": b.KeyClass,
			"key":      map[string]any{"keyId": b.Key.ID, "publicKeyJwk": jwk},
		},
	}, nil
}

func formatTime(t time.Time) (string, error) {
	if t.IsZero() || t.Nanosecond() != 0 {
		return "", errors.New("keybinding: a time is zero or not to the second")
	}
	return t.UTC().Format(timeLayout), nil
}

func sign(signer crypto.Signer, issuer, keyFragment string, body map[string]any) ([]byte, error) {
	proof, err := vc.CreateProof(signer, issuer, keyFragment, issuer+"#"+keyFragment, body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		return nil, fmt.Errorf("keybinding: sign: %w", err)
	}
	wire := make(map[string]any, len(body)+1)
	for k, v := range body {
		wire[k] = v
	}
	proofMap := map[string]any{
		"type": proof.Type, "cryptosuite": proof.Cryptosuite, "verificationMethod": proof.VerificationMethod,
		"proofPurpose": proof.ProofPurpose, "created": proof.Created, "proofValue": proof.ProofValue,
	}
	if proof.Context != nil {
		proofMap["@context"] = proof.Context
	}
	wire["proof"] = proofMap
	return jcs.CanonicalizeRFC8785(wire)
}

// jwkMembers are the members RFC 7638 hashes, per kty; jwkCurves the one
// curve each kty that has one may name.
var (
	jwkMembers = map[string][]string{
		"OKP": {"crv", "kty", "x"},
		"EC":  {"crv", "kty", "x", "y"},
		"RSA": {"e", "kty", "n"},
	}
	jwkCurves = map[string]string{"OKP": "Ed25519", "EC": "P-256"}
)

// checkJWK refuses a JWK that is not a usable key in its one spelling.
func checkJWK(jwk map[string]any) error {
	kty, _ := jwk["kty"].(string)
	members, ok := jwkMembers[kty]
	if !ok || len(jwk) != len(members) {
		return fmt.Errorf("keybinding: JWK of kty %q with members other than %v", kty, members)
	}
	vals := map[string][]byte{}
	for _, m := range members {
		s, ok := jwk[m].(string)
		if !ok || s == "" {
			return fmt.Errorf("keybinding: JWK member %q is missing or not a string", m)
		}
		if m == "kty" || m == "crv" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s {
			return fmt.Errorf("keybinding: JWK member %q is not canonical unpadded base64url", m)
		}
		vals[m] = raw
	}
	if crv, ok := jwkCurves[kty]; ok && jwk["crv"] != crv {
		return fmt.Errorf("keybinding: JWK of kty %s must be on %s", kty, crv)
	}
	switch kty {
	case "OKP":
		if err := ed25519.ValidatePublicKey(vals["x"]); err != nil {
			return fmt.Errorf("keybinding: JWK: %w", err)
		}
	case "EC":
		if len(vals["x"]) != 32 || len(vals["y"]) != 32 {
			return errors.New("keybinding: JWK of P-256 needs 32-byte x and y")
		}
		if err := es256.ValidatePublicKey(append(append([]byte{0x04}, vals["x"]...), vals["y"]...)); err != nil {
			return fmt.Errorf("keybinding: JWK: %w", err)
		}
	case "RSA":
		n, e := vals["n"], vals["e"]
		if n[0] == 0 || e[0] == 0 || len(e) > 4 {
			return errors.New("keybinding: JWK of RSA with a leading zero octet or an oversized e")
		}
		pub := &stdrsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if err := rs256.ValidatePublicKey(x509.MarshalPKCS1PublicKey(pub)); err != nil {
			return fmt.Errorf("keybinding: JWK: %w", err)
		}
	}
	return nil
}

// The @context of a binding and of a status list.
var (
	bindingContexts    = []any{vc.ContextCredentialsV2, vc.ContextDplaaxVCV1}
	statusListContexts = []any{vc.ContextCredentialsV2}
)

// errNotMade is a Verifier's answer when it was not made by NewVerifier.
var errNotMade = errors.New("keybinding: Verifier not made by NewVerifier")

// Anchor is the part of the relying party's trust anchor for an issuer that
// this package uses.
type Anchor struct {
	Issuer       string        // the issuer's DID
	IssuanceKeys []string      // the verification methods it issues bindings and status lists with
	MaxValidity  time.Duration // the longest validUntil − validFrom it may give
	MaxStatusAge time.Duration // how old its held status list may be
}

// Verifier verifies key bindings and status lists for one relying party.
type Verifier struct {
	sig      *vc.Verifier
	audience string
	skew     time.Duration
}

// NewVerifier returns a Verifier for the relying party audience, establishing
// issuers' signatures through sig and allowing skew of clock difference.
func NewVerifier(sig *vc.Verifier, audience string, skew time.Duration) (*Verifier, error) {
	switch {
	case sig == nil:
		return nil, errors.New("keybinding: no vc.Verifier")
	case audience == "":
		return nil, errors.New("keybinding: no audience")
	case skew < 0:
		return nil, errors.New("keybinding: negative clock skew")
	}
	return &Verifier{sig: sig, audience: audience, skew: skew}, nil
}

// signed reads raw and checks that the anchor's issuer signed it with one of
// the anchor's issuance keys, under the W3C eddsa-jcs-2022 contract, that its
// @context is contexts and its type is VerifiableCredential and typ, and that
// it carries no unsafe number. It returns the body, its content address and
// the verification method that signed it. An unestablished signature (the
// issuer's document or the lifecycle unavailable) is
// ErrSignatureUnestablished; a context error is returned as is.
func (v *Verifier) signed(ctx context.Context, raw []byte, a Anchor, typ string, contexts []any) (map[string]any, string, string, error) {
	var cred vc.Credential
	if err := cred.UnmarshalJSON(raw); err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	res, err := v.sig.VerifySignerAuthenticity(ctx, &cred)
	if err != nil {
		return nil, "", "", err
	}
	switch {
	case res.State == vc.ConfidenceIndeterminate:
		return nil, "", "", fmt.Errorf("%w: %s", ErrSignatureUnestablished, cred.Issuer())
	case res.State != vc.ConfidenceVerified,
		res.SuiteContract != vc.ContractW3CEdDSAJCS2022,
		res.Issuer != a.Issuer,
		!slices.Contains(a.IssuanceKeys, res.VerificationMethod):
		return nil, "", "", fmt.Errorf("%w: %s (%v, %s, %s)", ErrSignature, cred.Issuer(), res.State, res.SuiteContract, res.VerificationMethod)
	}
	body := cred.Body()
	if err := canon.AdmitSafeNumbers(body); err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if got, _ := body["@context"].([]any); !slices.Equal(got, contexts) {
		return nil, "", "", fmt.Errorf("%w: @context is not %v", ErrMalformed, contexts)
	}
	if types := cred.Types(); len(types) != 2 || types[0] != "VerifiableCredential" || types[1] != typ {
		return nil, "", "", fmt.Errorf("%w: type is not [VerifiableCredential %s]", ErrMalformed, typ)
	}
	hash, err := cred.Hash()
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return body, hash, res.VerificationMethod, nil
}

// VerifyBinding checks raw against the anchor and the held status list at at:
// the anchor's issuer signed it with an issuance key under the W3C
// eddsa-jcs-2022 contract; it is a well-formed KeyBindingCredential with no
// unsafe number; at is in [validFrom − skew, validUntil + skew) and the
// period is no longer than the anchor's maximum; the status list is the
// issuer's, current, and does not mark the binding; and the audience is this
// Verifier's. It returns the binding. Whether the issuer may bind what it
// binds (its scope) is the caller's to check.
func (v *Verifier) VerifyBinding(ctx context.Context, raw []byte, a Anchor, list *StatusList, at time.Time) (Binding, error) {
	if v == nil || v.sig == nil {
		return Binding{}, errNotMade
	}
	if at.IsZero() {
		return Binding{}, fmt.Errorf("%w: no time to verify at", ErrNotValidAt)
	}
	body, _, _, err := v.signed(ctx, raw, a, TypeKeyBinding, bindingContexts)
	if err != nil {
		return Binding{}, err
	}
	b, err := readBinding(body)
	if err != nil {
		return Binding{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if at.Before(b.ValidFrom.Add(-v.skew)) || !at.Before(b.ValidUntil.Add(v.skew)) {
		return Binding{}, fmt.Errorf("%w: %s until %s", ErrNotValidAt, b.ValidFrom.Format(timeLayout), b.ValidUntil.Format(timeLayout))
	}
	if b.ValidUntil.Sub(b.ValidFrom) > a.MaxValidity {
		return Binding{}, ErrValidityTooLong
	}
	if err := v.current(list, a, at); err != nil {
		return Binding{}, err
	}
	if list.id != b.Status.List {
		return Binding{}, fmt.Errorf("%w: its status list %q is not the one held (%q)", ErrStatusListStale, b.Status.List, list.id)
	}
	revoked, err := list.Revoked(b.Status.Index)
	if err != nil {
		return Binding{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if revoked {
		return Binding{}, ErrRevoked
	}
	if b.Audience != v.audience {
		return Binding{}, fmt.Errorf("%w: %q", ErrAudience, b.Audience)
	}
	return b, nil
}

// current refuses a list that is not the anchor's issuer's current list at
// at: none, another issuer's, signed with a key no longer among the anchor's
// issuance keys, not yet valid, older than the anchor's maximum age, or past
// its validUntil (each with the clock skew).
func (v *Verifier) current(list *StatusList, a Anchor, at time.Time) error {
	switch {
	case list == nil, list.issuer != a.Issuer, !slices.Contains(a.IssuanceKeys, list.signer):
		return fmt.Errorf("%w: none held for %s", ErrStatusListStale, a.Issuer)
	case at.IsZero():
		return fmt.Errorf("%w: no time to check the list at", ErrStatusListStale)
	case at.Before(list.validFrom.Add(-v.skew)):
		return fmt.Errorf("%w: the list is valid only from %s", ErrStatusListStale, list.validFrom.Format(timeLayout))
	case at.Sub(list.validFrom) > a.MaxStatusAge, !at.Before(list.validUntil.Add(v.skew)):
		return fmt.Errorf("%w: the one held is from %s", ErrStatusListStale, list.validFrom.Format(timeLayout))
	}
	return nil
}

func readBinding(body map[string]any) (Binding, error) {
	subj, ok := body["credentialSubject"].(map[string]any)
	if !ok {
		return Binding{}, errors.New("credentialSubject is not an object")
	}
	status, ok := body["credentialStatus"].(map[string]any)
	if !ok || len(status) != 4 || status["type"] != statusEntryType || status["statusPurpose"] != statusPurpose {
		return Binding{}, errors.New("credentialStatus is not a revocation BitstringStatusListEntry of four members (no statusSize, no statusMessage)")
	}
	key, ok := subj["key"].(map[string]any)
	if !ok || len(key) != 2 {
		return Binding{}, errors.New("credentialSubject.key is not an object of keyId and publicKeyJwk")
	}
	jwk, ok := key["publicKeyJwk"].(map[string]any)
	if !ok {
		return Binding{}, errors.New("key.publicKeyJwk is not an object")
	}
	if err := checkJWK(jwk); err != nil {
		return Binding{}, err
	}
	rawRoles, ok := subj["roles"].([]any)
	if !ok {
		return Binding{}, errors.New("credentialSubject.roles is not a list")
	}
	roles := make([]string, len(rawRoles))
	for i, r := range rawRoles {
		s, ok := r.(string)
		if !ok || s == "" || slices.Contains(roles[:i], s) {
			return Binding{}, errors.New("a role is not a non-empty string, or repeats")
		}
		roles[i] = s
	}
	b := Binding{Roles: roles, Key: Key{PublicKeyJWK: jwk}}
	for _, f := range []struct {
		dst *string
		m   map[string]any
		k   string
	}{
		{&b.Issuer, body, "issuer"}, {&b.Subject, subj, "id"}, {&b.Kind, subj, "kind"},
		{&b.Audience, subj, "audience"}, {&b.KeyClass, subj, "keyClass"}, {&b.Key.ID, key, "keyId"},
		{&b.Status.List, status, "statusListCredential"},
	} {
		s, ok := f.m[f.k].(string)
		if !ok || s == "" {
			return Binding{}, fmt.Errorf("%s is missing or not a string", f.k)
		}
		*f.dst = s
	}
	var err error
	if b.Status.Index, err = parseIndex(status["statusListIndex"]); err != nil {
		return Binding{}, err
	}
	if b.ValidFrom, err = parseTime(body["validFrom"]); err != nil {
		return Binding{}, err
	}
	if b.ValidUntil, err = parseTime(body["validUntil"]); err != nil {
		return Binding{}, err
	}
	if !b.ValidUntil.After(b.ValidFrom) {
		return Binding{}, errors.New("validUntil is not after validFrom")
	}
	return b, nil
}

func parseIndex(v any) (uint64, error) {
	s, ok := v.(string)
	if !ok || s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("statusListIndex is not a decimal string without leading zeros")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("statusListIndex is not a decimal string without leading zeros")
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseTime(v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, errors.New("a time is missing or not a string")
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Format(timeLayout) != s {
		return time.Time{}, fmt.Errorf("time %q is not UTC to the second", s)
	}
	return t, nil
}

// StatusList is a verified revocation list. Only VerifyStatusList makes one;
// its fields cannot be changed. A relying party keeps the raw list it was made
// from (a StatusList is not serialized) and verifies it again after a restart:
// with no held list, any current list is accepted. A kept list that no longer
// verifies (older than the anchor's maximum age, or its key gone from the
// anchor) is not held, so it guards none of its marks: keeping the marks seen
// is then the relying party's.
type StatusList struct {
	issuer     string
	id         string
	validFrom  time.Time
	validUntil time.Time
	signer     string // the verification method that signed it
	hash       string // the content address of its body, to tell a list from another with the same validFrom
	bits       []byte
}

// Issuer, ID, ValidFrom and ValidUntil are the list's, as signed.
func (l *StatusList) Issuer() string        { return l.issuer }
func (l *StatusList) ID() string            { return l.id }
func (l *StatusList) ValidFrom() time.Time  { return l.validFrom }
func (l *StatusList) ValidUntil() time.Time { return l.validUntil }

// Revoked reports whether index is marked. An index past the list, and a nil
// list, are errors.
func (l *StatusList) Revoked(index uint64) (bool, error) {
	if l == nil {
		return false, errors.New("keybinding: no status list")
	}
	if index >= uint64(len(l.bits))*8 {
		return false, fmt.Errorf("keybinding: index %d past a list of %d", index, uint64(len(l.bits))*8)
	}
	return l.bits[index/8]&(0x80>>(index%8)) != 0, nil
}

// IssueStatusList signs the issuer's revocation list id, valid from validFrom
// until validUntil, of size entries (at least MinStatusListSize, a multiple of
// 8), with revoked marked. A revocation is not reversible: an index marked
// stays marked in every later list of id, and is not given to another binding
// (a relying party refuses a later list that clears a mark it holds, with
// ErrStatusListRevocationCleared).
func IssueStatusList(signer crypto.Signer, issuer, keyFragment, id string, validFrom, validUntil time.Time, revoked []uint64, size uint64) ([]byte, error) {
	if size < MinStatusListSize || size%8 != 0 || size/8 > MaxStatusListBytes {
		return nil, fmt.Errorf("keybinding: a status list of %d entries", size)
	}
	bits := make([]byte, size/8)
	for _, i := range revoked {
		if i >= size {
			return nil, fmt.Errorf("keybinding: index %d past a list of %d", i, size)
		}
		bits[i/8] |= 0x80 >> (i % 8)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(bits); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return issueStatusListEncoded(signer, issuer, keyFragment, id, validFrom, validUntil, "u"+base64.RawURLEncoding.EncodeToString(gz.Bytes()))
}

func issueStatusListEncoded(signer crypto.Signer, issuer, keyFragment, id string, validFrom, validUntil time.Time, encoded string) ([]byte, error) {
	if id == "" || !validUntil.After(validFrom) {
		return nil, errors.New("keybinding: a status list needs an id and validUntil after validFrom")
	}
	from, err := formatTime(validFrom)
	if err != nil {
		return nil, err
	}
	until, err := formatTime(validUntil)
	if err != nil {
		return nil, err
	}
	return sign(signer, issuer, keyFragment, map[string]any{
		"@context":   []any{vc.ContextCredentialsV2},
		"type":       []any{"VerifiableCredential", TypeStatusList},
		"id":         id,
		"issuer":     issuer,
		"validFrom":  from,
		"validUntil": until,
		"credentialSubject": map[string]any{
			"id":            id + "-list", // the list itself, as the credential's subject
			"type":          statusListSubjectType,
			"statusPurpose": statusPurpose,
			"encodedList":   encoded,
		},
	})
}

// VerifyStatusList checks raw against the anchor at at — signed by the
// anchor's issuer with an issuance key, a well-formed revocation
// BitstringStatusListCredential whose id is a DID URL of the issuer
// (<issuer>#fragment), within MaxStatusListBytes once expanded, and current
// (at at, within the Verifier's clock skew of its validFrom and validUntil, and
// no older than the anchor's maximum age) — and returns it, or held when raw is
// held again (the same list is not a step back). held must be a list of the same id and issuer.
// A list whose validFrom is not later than held's, or the same validFrom with
// another body, is ErrStatusListRewound: a list only moves forward. A later
// list that leaves unmarked an entry held marks (an entry past its end is
// unmarked) is ErrStatusListRevocationCleared: a revocation is not reversible,
// so an issuer restored to an older state cannot undo one in the list held
// (only a held list guards its marks; see StatusList). Whatever it returns is
// current at at.
func (v *Verifier) VerifyStatusList(ctx context.Context, raw []byte, a Anchor, held *StatusList, at time.Time) (*StatusList, error) {
	if v == nil || v.sig == nil {
		return nil, errNotMade
	}
	body, hash, signer, err := v.signed(ctx, raw, a, TypeStatusList, statusListContexts)
	if err != nil {
		return nil, err
	}
	l, err := readStatusList(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if abs, err := did.AbsoluteKeyID(a.Issuer, l.id); err != nil || abs != l.id {
		return nil, fmt.Errorf("%w: the list id %q is not a DID URL <%s>#fragment", ErrMalformed, l.id, a.Issuer)
	}
	l.signer, l.hash = signer, hash
	out := l
	if held != nil {
		switch {
		case held.issuer != a.Issuer || held.id != l.id:
			return nil, fmt.Errorf("%w: list %q of %s, held %q of %s", ErrMalformed, l.id, a.Issuer, held.id, held.issuer)
		case l.validFrom.Equal(held.validFrom) && l.hash == held.hash:
			out = held
		case !l.validFrom.After(held.validFrom):
			return nil, fmt.Errorf("%w: from %s, held from %s", ErrStatusListRewound, l.validFrom.Format(timeLayout), held.validFrom.Format(timeLayout))
		default:
			if i, ok := firstCleared(held, l); ok {
				return nil, fmt.Errorf("%w: entry %d", ErrStatusListRevocationCleared, i)
			}
		}
	}
	if err := v.current(out, a, at); err != nil {
		return nil, err
	}
	return out, nil
}

// firstCleared returns the first entry held marks and l does not; an entry
// past l's end is unmarked in l.
func firstCleared(held, l *StatusList) (uint64, bool) {
	for i, b := range held.bits {
		if i < len(l.bits) {
			b &^= l.bits[i]
		}
		if b == 0 {
			continue
		}
		j := uint64(0)
		for b&(0x80>>j) == 0 {
			j++
		}
		return uint64(i)*8 + j, true
	}
	return 0, false
}

func readStatusList(body map[string]any) (*StatusList, error) {
	subj, ok := body["credentialSubject"].(map[string]any)
	if !ok || subj["type"] != statusListSubjectType || subj["statusPurpose"] != statusPurpose {
		return nil, errors.New("credentialSubject is not a revocation BitstringStatusList")
	}
	l := &StatusList{}
	issuer, ok1 := body["issuer"].(string)
	id, ok2 := body["id"].(string)
	encoded, ok3 := subj["encodedList"].(string)
	if !ok1 || !ok2 || !ok3 || id == "" || len(encoded) < 2 || encoded[0] != 'u' {
		return nil, errors.New("issuer, id or encodedList is missing")
	}
	l.issuer, l.id = issuer, id
	var err error
	if l.validFrom, err = parseTime(body["validFrom"]); err != nil {
		return nil, err
	}
	if l.validUntil, err = parseTime(body["validUntil"]); err != nil {
		return nil, err
	}
	if !l.validUntil.After(l.validFrom) {
		return nil, errors.New("validUntil is not after validFrom")
	}
	gz, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil || base64.RawURLEncoding.EncodeToString(gz) != encoded[1:] {
		return nil, errors.New("encodedList is not canonical multibase base64url")
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("encodedList: %v", err)
	}
	bits, err := io.ReadAll(io.LimitReader(r, MaxStatusListBytes+1))
	if err != nil {
		return nil, fmt.Errorf("encodedList: %v", err)
	}
	if len(bits) > MaxStatusListBytes {
		return nil, fmt.Errorf("encodedList expands past %d bytes", MaxStatusListBytes)
	}
	if uint64(len(bits))*8 < MinStatusListSize {
		return nil, fmt.Errorf("a list of %d entries, under %d", len(bits)*8, MinStatusListSize)
	}
	l.bits = bits
	return l, nil
}
