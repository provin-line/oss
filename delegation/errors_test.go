package delegation_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// The sentinels are constants: these lines stop compiling if one is not.
const (
	_ = delegation.ErrMalformed
	_ = delegation.ErrOwnerBinding
	_ = delegation.ErrProofPolicy
	_ = delegation.ErrScoped
	_ = delegation.ErrIssuerNotFound
	_ = delegation.ErrSignatureInvalid
	_ = delegation.ErrSignatureUnestablished
)

// classes is every sentinel a refusal of Verify or VerifyFor is.
var classes = []delegation.Error{
	delegation.ErrMalformed,
	delegation.ErrOwnerBinding,
	delegation.ErrProofPolicy,
	delegation.ErrScoped,
	delegation.ErrIssuerNotFound,
	delegation.ErrSignatureInvalid,
	delegation.ErrSignatureUnestablished,
	delegation.ErrNotForIdentity,
}

// classesOf is the sentinels of classes that err is (errors.Is).
func classesOf(err error) []delegation.Error {
	var out []delegation.Error
	for _, c := range classes {
		if errors.Is(err, c) {
			out = append(out, c)
		}
	}
	return out
}

func TestSentinelsAreDistinct(t *testing.T) {
	seen := map[delegation.Error]bool{}
	for _, c := range classes {
		if seen[c] {
			t.Errorf("%q is two sentinels", c)
		}
		seen[c] = true
	}
}

// errResolver answers every resolution with err.
type errResolver struct{ err error }

func (r errResolver) Resolve(context.Context, string) (*did.DIDDocument, error) { return nil, r.err }

// errVerifier is a signature verifier that fails with err.
type errVerifier struct{ err error }

func (v errVerifier) Verify([]byte, []byte, []byte) (bool, error) { return false, v.err }
func (errVerifier) Algorithm() string                             { return "Ed25519" }

// refusalCase is a delegation Verify refuses, the text it refuses it with,
// the one sentinel the refusal is, an error like the one of another package
// it keeps (nil for none), and the sentinels that error is.
type refusalCase struct {
	cred     *delegation.DelegationCredential
	resolver resolver.Resolver
	verifier crypto.Verifier
	text     string
	class    delegation.Error
	wraps    error
	keeps    []error
}

// holdsErrorLike reports whether err or an error it wraps is of like's type
// and reads like's text.
func holdsErrorLike(err, like error) bool {
	if err == nil {
		return false
	}
	if reflect.TypeOf(err) == reflect.TypeOf(like) && err.Error() == like.Error() {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return holdsErrorLike(u.Unwrap(), like)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if holdsErrorLike(e, like) {
				return true
			}
		}
	}
	return false
}

// refusalCases is a case for each check of Verify, by the check's text.
func refusalCases(t *testing.T) map[string]refusalCase {
	t.Helper()
	const (
		otherOwner  = "did:dplaax:poc.dplaax.dev:org:other"
		pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
		imposter    = "did:dplaax:poc.dplaax.dev:org:imposter"
		didWeb      = "did:web:example.com"
		userDID     = "did:dplaax:poc.dplaax.dev:user:alice"
	)
	signer, r := fixture(t, ownerDID)
	doc, err := r.Resolve(context.Background(), ownerDID)
	if err != nil {
		t.Fatal(err)
	}
	built := func(mutate func(*delegation.DelegationCredential)) *delegation.DelegationCredential {
		t.Helper()
		cred, err := delegation.Build(signer, ownerDID, sampleSubject())
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if mutate != nil {
			mutate(cred)
		}
		return cred
	}
	// signedBy is a delegation naming issuer and subject: they are checked
	// before the signature is.
	signedBy := func(issuer string, subject string) *delegation.DelegationCredential {
		t.Helper()
		return built(func(c *delegation.DelegationCredential) {
			c.Issuer, c.CredentialSubject.DelegatedBy, c.CredentialSubject.ID = issuer, issuer, subject
		})
	}
	other, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherKey := local.New()
	otherKey.Add(signingDoc(ownerDID, other.PublicKey))
	notForAssertion := local.New()
	vm, err := did.NewMultikeyVerificationMethod(ownerDID+"#signing", ownerDID, other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	unlisted := did.New(did.DocumentFields{Context: did.IssuedDocumentContexts(), ID: ownerDID, Controller: ownerDID, VerificationMethod: []did.VerificationMethod{vm}})
	notForAssertion.Add(unlisted)

	_, createdErr := time.Parse(time.RFC3339, "not-a-date")
	_, webErr := dplaax.Parse(didWeb)
	_, emptyErr := dplaax.Parse("")
	user, err := dplaax.Parse(userDID)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := dplaax.Parse(pipelineDID)
	if err != nil {
		t.Fatal(err)
	}
	_, proofValueErr := (&vc.DataIntegrityProof{ProofValue: "not base58btc"}).ProofValueBytes()
	_, notFoundErr := local.New().Resolve(context.Background(), ownerDID)
	_, _, noKeyErr := did.ExtractPublicKeyAndEncoding(doc, ownerDID+"#other", did.RelationshipAssertionMethod)
	_, _, unlistedErr := did.ExtractPublicKeyAndEncoding(unlisted, ownerDID+"#signing", did.RelationshipAssertionMethod)
	unreachable := errors.New("registry unreachable")
	ended := fmt.Errorf("resolve: %w", context.Canceled)
	badKey := errors.New("public key of the wrong size")
	long := ownerDID + "#" + strings.Repeat("f", 64<<10)
	_, _, longErr := did.ExtractPublicKeyAndEncoding(doc, long, did.RelationshipAssertionMethod)
	cut, cutShort := excerpt.Of(longErr.Error(), 512)
	if !cutShort {
		t.Fatalf("the long key reference's error is not cut: %d bytes", len(longErr.Error()))
	}
	stray, err := did.NewMultikeyVerificationMethod(otherOwner+"#stray", ownerDID, other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	genuine, err := r.Resolve(context.Background(), ownerDID)
	if err != nil {
		t.Fatal(err)
	}
	withStray := did.New(did.DocumentFields{
		Context: did.IssuedDocumentContexts(), ID: ownerDID, Controller: ownerDID,
		VerificationMethod: append(genuine.VerificationMethod(), stray),
		AssertionMethod:    genuine.AssertionMethod(),
	})
	strayDoc := local.New()
	strayDoc.Add(withStray)
	_, _, strayErr := did.ExtractPublicKeyAndEncoding(withStray, ownerDID+"#signing", did.RelationshipAssertionMethod)
	_, shapeErr := vc.ClassifyProof(vc.CryptosuiteEdDSAJCS2022, false, did.EncodingMultikey)

	return map[string]refusalCase{
		"no credential": {
			text: "delegation: nil credential", class: delegation.ErrMalformed,
		},
		"no proof": {
			cred: built(func(c *delegation.DelegationCredential) { c.Proof = nil }),
			text: "delegation: unsigned credential", class: delegation.ErrMalformed,
		},
		"a proof for another purpose": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.ProofPurpose = "authentication" }),
			text:  `delegation: proof type/purpose "DataIntegrityProof"/"authentication" not "DataIntegrityProof"/"assertionMethod"`,
			class: delegation.ErrProofPolicy,
		},
		"a proof of another type": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.Type = "Ed25519Signature2020" }),
			text:  `delegation: proof type/purpose "Ed25519Signature2020"/"assertionMethod" not "DataIntegrityProof"/"assertionMethod"`,
			class: delegation.ErrProofPolicy,
		},
		"another cryptosuite": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.Cryptosuite = "eddsa-rdfc-2022" }),
			text:  `delegation: unsupported cryptosuite "eddsa-rdfc-2022" (want "eddsa-jcs-2022")`,
			class: delegation.ErrProofPolicy,
		},
		"a created time that does not parse": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.Created = "not-a-date" }),
			text:  `delegation: proof.created "not-a-date" is not RFC3339: ` + createdErr.Error(),
			class: delegation.ErrProofPolicy, wraps: createdErr,
		},
		"no DelegationCredential type": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Type = []string{"VerifiableCredential"} }),
			text:  `delegation: type "VerifiableCredential" missing VerifiableCredential / DelegationCredential`,
			class: delegation.ErrMalformed,
		},
		"no VerifiableCredential type": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Type = []string{"DelegationCredential"} }),
			text:  `delegation: type "DelegationCredential" missing VerifiableCredential / DelegationCredential`,
			class: delegation.ErrMalformed,
		},
		"a scope": {
			cred:  built(func(c *delegation.DelegationCredential) { c.CredentialSubject.Scope = []string{"process:sign"} }),
			text:  "delegation: credentialSubject.scope is present (1 token(s)); the provin profile does not accept scoped delegations",
			class: delegation.ErrScoped,
		},
		"an empty scope": {
			cred:  built(func(c *delegation.DelegationCredential) { c.CredentialSubject.Scope = []string{} }),
			text:  "delegation: credentialSubject.scope is present (0 token(s)); the provin profile does not accept scoped delegations",
			class: delegation.ErrScoped,
		},
		"a delegatedBy that is not the issuer": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Issuer = otherOwner }),
			text:  `delegation: delegatedBy "` + ownerDID + `" != issuer "` + otherOwner + `"`,
			class: delegation.ErrMalformed,
		},
		"an empty issuer": {
			cred:  signedBy("", processDID),
			text:  "delegation: issuer is not a did:dplaax identifier: " + emptyErr.Error(),
			class: delegation.ErrMalformed, wraps: emptyErr,
			keeps: []error{dplaax.ErrSyntax},
		},
		"an empty delegatedBy": {
			cred:  built(func(c *delegation.DelegationCredential) { c.CredentialSubject.DelegatedBy = "" }),
			text:  `delegation: delegatedBy "" != issuer "` + ownerDID + `"`,
			class: delegation.ErrMalformed,
		},
		"an empty subject id": {
			cred:  signedBy(ownerDID, ""),
			text:  "delegation: subject id is not a did:dplaax identifier: " + emptyErr.Error(),
			class: delegation.ErrMalformed, wraps: emptyErr,
			keeps: []error{dplaax.ErrSyntax},
		},
		"an issuer that is not did:dplaax": {
			cred:  signedBy(didWeb, processDID),
			text:  "delegation: issuer is not a did:dplaax identifier: " + webErr.Error(),
			class: delegation.ErrOwnerBinding, wraps: webErr,
			keeps: []error{dplaax.ErrSyntax},
		},
		"an issuer the deployment does not accept": {
			cred:  signedBy(userDID, processDID),
			text:  "delegation: issuer: " + dplaax.ValidateDID(user).Error(),
			class: delegation.ErrOwnerBinding, wraps: dplaax.ValidateDID(user),
		},
		"an issuer that is not an Owner": {
			cred:  signedBy(pipelineDID, processDID),
			text:  "delegation: " + dplaax.RequireOwner(pipeline).Error(),
			class: delegation.ErrOwnerBinding, wraps: dplaax.RequireOwner(pipeline),
		},
		"a subject that is not did:dplaax": {
			cred:  signedBy(ownerDID, didWeb),
			text:  "delegation: subject id is not a did:dplaax identifier: " + webErr.Error(),
			class: delegation.ErrOwnerBinding, wraps: webErr,
			keeps: []error{dplaax.ErrSyntax},
		},
		"an Owner as subject": {
			cred:  signedBy(ownerDID, ownerDID),
			text:  `delegation: subject "` + ownerDID + `" is neither a pipeline nor a process DID`,
			class: delegation.ErrOwnerBinding,
		},
		"a subject under another Owner": {
			cred:  signedBy(ownerDID, otherOwner+":pipeline:p1"),
			text:  `delegation: subject "` + otherOwner + `:pipeline:p1" is not under the issuing owner "` + ownerDID + `"`,
			class: delegation.ErrOwnerBinding,
		},
		"a verificationMethod of another DID": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.VerificationMethod = otherOwner + "#signing" }),
			text:  `delegation: verificationMethod "` + otherOwner + `#signing" does not name the issuer "` + ownerDID + `"`,
			class: delegation.ErrProofPolicy,
		},
		"a verificationMethod with no fragment": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.VerificationMethod = ownerDID }),
			text:  `delegation: verificationMethod "` + ownerDID + `" does not name the issuer "` + ownerDID + `"`,
			class: delegation.ErrProofPolicy,
		},
		"a proofValue that does not decode": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.ProofValue = "not base58btc" }),
			text:  "delegation: " + proofValueErr.Error(),
			class: delegation.ErrProofPolicy, wraps: proofValueErr,
		},
		"an issuer with no document": {
			cred: built(nil), resolver: local.New(),
			text:  "delegation: resolve issuer: " + notFoundErr.Error(),
			class: delegation.ErrIssuerNotFound, wraps: notFoundErr,
			keeps: []error{resolver.ErrNotFound},
		},
		"a resolver that does not answer": {
			cred: built(nil), resolver: errResolver{unreachable},
			text:  "delegation: resolve issuer: registry unreachable",
			class: delegation.ErrSignatureUnestablished, wraps: unreachable,
			keeps: []error{unreachable},
		},
		"a resolution the context ended": {
			cred: built(nil), resolver: errResolver{ended},
			text:  "delegation: resolve issuer: resolve: context canceled",
			class: delegation.ErrSignatureUnestablished, wraps: ended,
			keeps: []error{context.Canceled},
		},
		"a resolver that answers nothing": {
			cred: built(nil), resolver: errResolver{nil},
			text:  "delegation: resolve issuer: no document and no error",
			class: delegation.ErrSignatureUnestablished,
		},
		"the document of another DID": {
			cred: built(nil), resolver: substitutingResolver{signingDocAs(imposter, ownerDID, other.PublicKey)},
			text:  `delegation: resolved document id "` + imposter + `" != issuer "` + ownerDID + `" (registry-substitution defense)`,
			class: delegation.ErrSignatureUnestablished,
		},
		"a key the document does not have": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.VerificationMethod = ownerDID + "#other" }),
			text:  "delegation: extract owner key: " + noKeyErr.Error(),
			class: delegation.ErrIssuerNotFound, wraps: noKeyErr,
		},
		"a key not listed for assertion": {
			cred: built(nil), resolver: notForAssertion,
			text:  "delegation: extract owner key: " + unlistedErr.Error(),
			class: delegation.ErrIssuerNotFound, wraps: unlistedErr,
		},
		"another key": {
			cred: built(nil), resolver: otherKey,
			text:  "delegation: vc: proof signature does not verify",
			class: delegation.ErrSignatureInvalid, wraps: errors.New("vc: proof signature does not verify"),
		},
		"a validFrom shifted within its second": {
			cred:  built(func(c *delegation.DelegationCredential) { c.ValidFrom = c.ValidFrom.Add(500 * time.Millisecond) }),
			text:  "delegation: vc: proof signature does not verify",
			class: delegation.ErrSignatureInvalid, wraps: errors.New("vc: proof signature does not verify"),
		},
		"a signature verifier that fails": {
			cred: built(nil), verifier: errVerifier{badKey},
			text:  "delegation: vc: verify proof signature: public key of the wrong size",
			class: delegation.ErrSignatureInvalid, wraps: fmt.Errorf("vc: verify proof signature: %w", badKey),
			keeps: []error{badKey},
		},
		"a key reference the text cuts": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.VerificationMethod = long }),
			text:  "delegation: extract owner key: " + cut,
			class: delegation.ErrIssuerNotFound, wraps: longErr,
		},
		"a method of the document in no form it accepts": {
			cred: built(nil), resolver: strayDoc,
			text:  "delegation: extract owner key: " + strayErr.Error(),
			class: delegation.ErrIssuerNotFound, wraps: strayErr,
			keeps: []error{did.ErrInvalidKeyReference},
		},
		"a proof with no @context": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.Context = nil }),
			text:  "delegation: " + shapeErr.Error(),
			class: delegation.ErrSignatureInvalid, wraps: shapeErr,
		},
		"a proof @context that does not mirror the credential's": {
			cred:  built(func(c *delegation.DelegationCredential) { c.Proof.Context = []any{vc.ContextCredentialsV2} }),
			text:  "delegation: vc: proof-local @context does not mirror the document @context",
			class: delegation.ErrSignatureInvalid, wraps: errors.New("vc: proof-local @context does not mirror the document @context"),
		},
	}
}

// Every refusal of Verify keeps its text and is exactly one of the sentinels,
// the one its check names; VerifyFor, for the identity the delegation names,
// refuses it alike. What another package returned stays reachable.
func TestVerify_EachRefusalIsOneSentinel(t *testing.T) {
	_, fixtureResolver := fixture(t, ownerDID)
	for name, c := range refusalCases(t) {
		t.Run(name, func(t *testing.T) {
			res, ver := c.resolver, c.verifier
			if res == nil {
				res = fixtureResolver
			}
			if ver == nil {
				ver = ed25519.Verifier{}
			}
			identity := processDID
			if c.cred != nil {
				identity = c.cred.CredentialSubject.ID
			}
			for entry, err := range map[string]error{
				"Verify":    delegation.Verify(context.Background(), ver, res, c.cred),
				"VerifyFor": delegation.VerifyFor(context.Background(), ver, res, c.cred, identity),
			} {
				if err == nil {
					t.Fatalf("%s: accepted, want %q", entry, c.text)
				}
				if err.Error() != c.text {
					t.Errorf("%s: text\n got %q\nwant %q", entry, err.Error(), c.text)
				}
				if got := classesOf(err); len(got) != 1 || got[0] != c.class {
					t.Errorf("%s: is %q, want only %q", entry, got, c.class)
				}
				if c.wraps != nil && !holdsErrorLike(err, c.wraps) {
					t.Errorf("%s: keeps no %T reading %q", entry, c.wraps, c.wraps)
				}
				for _, k := range c.keeps {
					if !errors.Is(err, k) {
						t.Errorf("%s: %q is not reachable", entry, k)
					}
				}
			}
		})
	}
}

// The created time's parse error stays reachable by errors.As.
func TestVerify_KeepsTheParseErrorInItsClass(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	cred.Proof.Created = "not-a-date"
	err = delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred)
	var pe *time.ParseError
	if !errors.As(err, &pe) || !errors.Is(err, delegation.ErrProofPolicy) {
		t.Errorf("err = %v, want ErrProofPolicy keeping a *time.ParseError", err)
	}
}

// A delegation presented for another identity is ErrNotForIdentity alone.
func TestVerifyFor_AnotherIdentityIsOnlyErrNotForIdentity(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	const another = ownerDID + ":pipeline:p1:process:proc2"
	err = delegation.VerifyFor(context.Background(), ed25519.Verifier{}, r, cred, another)
	want := `delegation: not for this identity: it names "` + processDID + `", not "` + another + `"`
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
	if got := classesOf(err); len(got) != 1 || got[0] != delegation.ErrNotForIdentity {
		t.Errorf("is %q, want only ErrNotForIdentity", got)
	}
}

// A delegation both entry points accept comes back as a nil error: an error
// interface holding a nil pointer would be non-nil here.
func TestVerify_AcceptsWithANilError(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	if err := delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred); err != nil {
		t.Errorf("Verify: %#v, want nil", err)
	}
	if err := delegation.VerifyFor(context.Background(), ed25519.Verifier{}, r, cred, processDID); err != nil {
		t.Errorf("VerifyFor: %#v, want nil", err)
	}
}

// An error from the resolver or the signature verifier the caller gives is
// kept as it is: a sentinel of this package it wraps is reachable beside the
// one the call attaches.
func TestVerify_KeepsASentinelTheCallersErrorWraps(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		resolver resolver.Resolver
		verifier crypto.Verifier
		attached delegation.Error
		wrapped  delegation.Error
	}{
		"a resolver's error": {
			resolver: errResolver{fmt.Errorf("upstream: %w", delegation.ErrSignatureInvalid)},
			verifier: ed25519.Verifier{},
			attached: delegation.ErrSignatureUnestablished, wrapped: delegation.ErrSignatureInvalid,
		},
		"a resolver's error that is a sentinel": {
			resolver: errResolver{delegation.ErrScoped},
			verifier: ed25519.Verifier{},
			attached: delegation.ErrSignatureUnestablished, wrapped: delegation.ErrScoped,
		},
		"a resolver's not-found": {
			resolver: errResolver{fmt.Errorf("upstream: %w: %w", resolver.ErrNotFound, delegation.ErrSignatureUnestablished)},
			verifier: ed25519.Verifier{},
			attached: delegation.ErrIssuerNotFound, wrapped: delegation.ErrSignatureUnestablished,
		},
		"a signature verifier's error": {
			resolver: r,
			verifier: errVerifier{fmt.Errorf("hsm: %w", delegation.ErrIssuerNotFound)},
			attached: delegation.ErrSignatureInvalid, wrapped: delegation.ErrIssuerNotFound,
		},
	} {
		err := delegation.Verify(context.Background(), c.verifier, c.resolver, cred)
		got := classesOf(err)
		if len(got) != 2 || !errors.Is(err, c.attached) || !errors.Is(err, c.wrapped) {
			t.Errorf("%s: is %q, want %q attached and %q kept", name, got, c.attached, c.wrapped)
		}
	}
}

// A refusal's text stays within the bound on what it quotes: the class adds
// nothing to it.
func TestVerify_ClassDoesNotLengthenTheText(t *testing.T) {
	signer, r := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	cred.Proof.VerificationMethod = ownerDID + "#" + strings.Repeat("f", 64<<10)
	err = delegation.Verify(context.Background(), ed25519.Verifier{}, r, cred)
	if err == nil || len(err.Error()) > 1024 || !errors.Is(err, delegation.ErrIssuerNotFound) {
		t.Errorf("err = %.200v (%d bytes), want ErrIssuerNotFound within 1 KiB", err, len(fmt.Sprint(err)))
	}
}

// askedError reads differently once its Is method has been called.
type askedError struct{ asked *bool }

func (e askedError) Error() string {
	if *e.asked {
		return "asked"
	}
	return "not asked"
}

func (e askedError) Is(error) bool {
	*e.asked = true
	return false
}

// The resolver's error is read for the text before it is classified.
func TestVerify_ReadsTheResolversErrorBeforeClassifyingIt(t *testing.T) {
	signer, _ := fixture(t, ownerDID)
	cred, err := delegation.Build(signer, ownerDID, sampleSubject())
	if err != nil {
		t.Fatal(err)
	}
	err = delegation.Verify(context.Background(), ed25519.Verifier{}, errResolver{askedError{new(bool)}}, cred)
	if want := "delegation: resolve issuer: not asked"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}
