package vc

import "github.com/provin-line/oss/canon/jcs"

// Credential is a verifiable credential of any type, secured with an embedded
// Data Integrity proof, as received. It is what Verifier.VerifySignerAuthenticity
// reads.
//
// It holds the wire form the way PipelinePassCredential does — the body (every
// member but the proof) is the single source of truth for signing and hashing,
// and the raw proof map round-trips byte-faithfully — but it carries no type's
// rules: no wire-form checks, no required type, no field grammar. A caller that
// accepts a particular type checks its rules on the body.
//
// The only construction path is UnmarshalJSON.
type Credential struct {
	body  map[string]any
	proof map[string]any
}

// UnmarshalJSON parses the wire form under strict-decoder rules (duplicate
// members, trailing data and a non-object proof are refused), keeping every
// member.
func (c *Credential) UnmarshalJSON(data []byte) error {
	body, proof, err := decodeWire(data)
	if err != nil {
		return err
	}
	c.body = body
	c.proof = proof
	return nil
}

// MarshalJSON emits the wire form (body plus proof) as RFC 8785 canonical bytes.
func (c *Credential) MarshalJSON() ([]byte, error) {
	return jcs.CanonicalizeRFC8785(wireDocument(c.body, c.proof))
}

// Issuer returns the issuer's identifier: the issuer member when it is a
// string, or its id when it is an object with a string id (the two forms the W3C
// data model allows). Any other value names no issuer, and Issuer returns "".
func (c *Credential) Issuer() string {
	switch v := c.body[keyIssuer].(type) {
	case string:
		return v
	case map[string]any:
		id, _ := v["id"].(string)
		return id
	default:
		return ""
	}
}

// Types returns the credential's type terms: the type member as a list of
// strings, or a single string as a list of one. A list with an entry that is
// not a string, and any other value, yields nil: a malformed type names no
// type.
func (c *Credential) Types() []string {
	switch v := c.body[keyType].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

// Body returns a defensive copy of the body (the signing scope, proof
// excluded).
func (c *Credential) Body() map[string]any {
	return deepCopyMap(c.body)
}

// Proof returns the typed proof view (a defensive copy); nil when unsigned.
// Proof members outside the view are not visible here but survive round-trips.
func (c *Credential) Proof() *DataIntegrityProof {
	return proofView(c.proof)
}

// Hash returns "sha256:<hex>" over the RFC 8785 canonical body — the
// credential's content address, computed as PipelinePassCredential.Hash
// computes it.
func (c *Credential) Hash() (string, error) {
	return jcs.HashRFC8785(c.body)
}
