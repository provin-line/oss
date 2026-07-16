package vc

import (
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/provin-line/oss/canon"
)

// Validate checks the claim against the protocol's claim grammar
// (credential.claim.grammar, credential.claim.bare-rejected,
// credential.claim.charset): a single <namespace>:<label> token with
// both parts nonempty. Space, control, and format characters (Unicode
// White_Space, Cc, Cf — including zero-width and bidi controls, which
// are display-spoofing vectors) and "+" (the deleted join operator's
// surface form) are rejected per credential.claim.charset; character
// classes beyond those — case, non-ASCII letters — are deliberately the
// profile's call. The spec pins the property snapshot to Unicode 15.0;
// this implementation judges via the Go unicode tables, which currently
// match (guarded by a unicode.Version test — a toolchain table bump
// requires re-auditing the class delta against the pinned snapshot).
// Grammar says nothing about claim meaning; semantics are pinned per
// claim by the profile that owns the namespace.
func (tc TransformationClaim) Validate() error {
	s := string(tc)
	if s == "" {
		return fmt.Errorf("transformationClaim must be present (credential.subject.transformation-claim)")
	}
	prefix, label, found := strings.Cut(s, ":")
	if !found || prefix == "" || label == "" {
		return fmt.Errorf("transformationClaim %q is not a single <namespace>:<label> token (credential.claim.grammar)", s)
	}
	if strings.Contains(label, ":") {
		return fmt.Errorf("transformationClaim %q is not a single <namespace>:<label> token (credential.claim.grammar)", s)
	}
	for _, part := range []string{prefix, label} {
		for _, r := range part {
			if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '+' {
				return fmt.Errorf("transformationClaim %q contains a character outside the token charset (credential.claim.charset)", s)
			}
		}
	}
	return nil
}

// provinClaimNamespace is the namespace whose registry this implementation,
// as a provin issuer, is bound by. Other namespaces are other profiles'.
const provinClaimNamespace = "provin"

// registeredProvinClaims is the provin profile's claim registry
// (profile.spec claim.registry.closed): the complete set of labels this
// implementation may EMIT under the provin namespace. Adding an entry is a
// profile version change first and a code change second — the registry's
// source of truth is rules/claim.yaml, and this set follows it.
var registeredProvinClaims = map[TransformationClaim]bool{
	ClaimFilter:        true,
	ClaimConvert:       true,
	ClaimFilterConvert: true,
	ClaimAggregate:     true,
	ClaimEnrich:        true,
	ClaimGenerate:      true,
	ClaimSinkReceipt:   true,
}

// enforceIssuanceRegistry rejects EMITTING an unregistered provin: label.
//
// Issuance-only, and the asymmetry is the profile's own: claim.registry.closed
// binds the issuer ("closed for ISSUANCE, not for verification"), while the
// receive path stays open-world (credential.claim.open-world-accept) so a
// newer node's label reaches an older node safely — by default, not by
// upgrade. Putting this check anywhere the receive path shares (such as
// ValidateTransformationClaim) would turn every future label addition into a
// coordinated fleet upgrade, which is the cost the open-world rule exists to
// avoid. Other namespaces pass untouched: their registries are not ours to
// enforce, and their grounding is already checked where all grounding is.
func (tc TransformationClaim) enforceIssuanceRegistry() error {
	prefix, _, _ := strings.Cut(string(tc), ":")
	if prefix != provinClaimNamespace {
		return nil
	}
	if !registeredProvinClaims[tc] {
		return fmt.Errorf("transformationClaim %q is not a label the provin profile registers — this issuer must not emit it (claim.registry.closed)", tc)
	}
	return nil
}

// knownContextGroundings maps the context IRIs whose documents this
// implementation knows byte-exactly to the claim-namespace prefixes those
// documents ground. A prefix mapping is a simple string term whose value
// ends in a JSON-LD gen-delim character — the JSON-LD 1.1 condition for a
// term to be usable as a compact-IRI prefix. ContextCredentialsV2 is a
// known document that grounds no claim namespace (vetted manually; the
// document is not embedded).
var knownContextGroundings = sync.OnceValue(func() map[string]map[string]string {
	return map[string]map[string]string{
		ContextCredentialsV2: {},
		ContextDplaaxVCV1:    embeddedGroundings(contextDplaaxVCV1Document),
		ContextProvinVCV1:    embeddedGroundings(contextProvinVCV1Document),
	}
})

// embeddedGroundings extracts the prefix mappings of an embedded context
// document. The documents are compile-time constants, so a parse failure
// is a build defect, not input — it panics.
func embeddedGroundings(document []byte) map[string]string {
	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := canon.NewStrictDecoder(document).Decode(&parsed); err != nil {
		panic(fmt.Sprintf("embedded context document is not valid JSON: %v", err))
	}
	return groundedPrefixes(parsed.Context)
}

// groundedPrefixes extracts prefix → vocabulary-URL mappings from a
// context object (the value of "@context", embedded or inline): simple
// string terms whose value ends in a JSON-LD gen-delim character — the
// JSON-LD 1.1 condition for a term to be usable as a compact-IRI prefix.
// Expanded term definitions ({"@id": …, "@prefix": true}) are not
// handled; the embedded documents do not use them, and the conformance
// context ledger pins their shape.
func groundedPrefixes(contextObject map[string]any) map[string]string {
	out := make(map[string]string)
	for term, def := range contextObject {
		if strings.HasPrefix(term, "@") {
			continue
		}
		url, ok := def.(string)
		if !ok || url == "" {
			continue
		}
		if strings.ContainsRune(":/?#[]@", rune(url[len(url)-1])) {
			out[term] = url
		}
	}
	return out
}

// ValidateTransformationClaim checks the credential's transformationClaim
// against the wire rules: presence (credential.subject.transformation-claim),
// the token grammar (credential.claim.grammar), and namespace grounding —
// some context document in @context must map the claim's prefix to a URL
// (credential.claim.grounding). Grounding is a structural check requiring
// no profile knowledge: a prefix grounded by a known context document or
// by an inline context object (whose mappings are right there in the
// document) passes; only an unknown context IRI is a grounding source
// this implementation cannot enumerate — there the grounding cannot be
// disproven and the open-world default applies
// (credential.claim.open-world-accept); a prefix that nothing grounds,
// with no unknown IRI left to ground it, fails closed.
func (c *PipelinePassCredential) ValidateTransformationClaim() error {
	subject, err := c.Subject()
	if err != nil {
		return err
	}
	// Diagnose a non-string wire value before the typed view collapses it
	// to "" and the failure reads as absence.
	if rawSubject, ok := c.body[keySubject].(map[string]any); ok {
		if raw, present := rawSubject[keyTransformationClaim]; present {
			if _, isString := raw.(string); !isString {
				return fmt.Errorf("transformationClaim is not a string (credential.claim.grammar)")
			}
		}
	}
	claim := subject.TransformationClaim
	if err := claim.Validate(); err != nil {
		return err
	}
	prefix, _, _ := strings.Cut(string(claim), ":")

	known := knownContextGroundings()
	sawUnknown := false
	contexts, ok := c.body[keyContext].([]any)
	if !ok {
		return fmt.Errorf("transformationClaim %q: @context is not an array, so nothing can ground namespace %q (credential.field.context)", claim, prefix)
	}
	for _, entry := range contexts {
		var groundings map[string]string
		switch e := entry.(type) {
		case string:
			groundings, ok = known[e]
			if !ok {
				sawUnknown = true // unknown IRI: unenumerable grounding source
				continue
			}
		case map[string]any:
			groundings = groundedPrefixes(e) // inline context: enumerable in place
		default:
			continue // scalar non-context entry grounds nothing
		}
		if _, grounded := groundings[prefix]; grounded {
			return nil
		}
	}
	if sawUnknown {
		return nil
	}
	return fmt.Errorf("transformationClaim %q: no context document in @context grounds namespace %q (credential.claim.grounding)", claim, prefix)
}
