package vc

import (
	"fmt"
	"strings"
	"sync"

	"github.com/provin-line/oss/canon"
)

// Validate checks the claim against the protocol's claim grammar
// (credential.claim.grammar, credential.claim.bare-rejected): a single
// <namespace>:<label> token with both parts nonempty. Whitespace and
// control bytes never appear in a token; "+" is excluded everywhere
// because the protocol deleted the join operator — a label containing
// "+" would resurrect its surface form, so it fails closed. Grammar says
// nothing about claim meaning; semantics are pinned per claim by the
// profile that owns the namespace.
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
			if r <= ' ' || r == 0x7f || r == '+' {
				return fmt.Errorf("transformationClaim %q contains a byte outside the token grammar (credential.claim.grammar)", s)
			}
		}
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
		ContextDplaaxVCV1:    groundedPrefixes(contextDplaaxVCV1Document),
		ContextProvinVCV1:    groundedPrefixes(contextProvinVCV1Document),
	}
})

// groundedPrefixes extracts prefix → vocabulary-URL mappings from an
// embedded context document. The documents are compile-time constants, so
// a parse failure is a build defect, not input — it panics.
func groundedPrefixes(document []byte) map[string]string {
	var parsed struct {
		Context map[string]any `json:"@context"`
	}
	if err := canon.NewStrictDecoder(document).Decode(&parsed); err != nil {
		panic(fmt.Sprintf("embedded context document is not valid JSON: %v", err))
	}
	out := make(map[string]string)
	for term, def := range parsed.Context {
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
// no profile knowledge: a prefix grounded by a known context document
// passes; when @context carries an entry this implementation cannot
// enumerate (an unknown IRI or an inline context object), the grounding
// cannot be disproven and the open-world default applies
// (credential.claim.open-world-accept); a prefix that no known document
// grounds, with no unknown entry left to ground it, fails closed.
func (c *PipelinePassCredential) ValidateTransformationClaim() error {
	subject, err := c.Subject()
	if err != nil {
		return err
	}
	claim := subject.TransformationClaim
	if err := claim.Validate(); err != nil {
		return err
	}
	prefix, _, _ := strings.Cut(string(claim), ":")

	known := knownContextGroundings()
	sawUnknown := false
	contexts, _ := c.body[keyContext].([]any)
	for _, entry := range contexts {
		iri, ok := entry.(string)
		if !ok {
			sawUnknown = true // inline context object: unknown grounding source
			continue
		}
		groundings, ok := known[iri]
		if !ok {
			sawUnknown = true
			continue
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
