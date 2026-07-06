package vc

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// contentAddressField enforces the sha256:<hex> grammar on a raw subject
// field: absence is acceptable unless required; ANY present value — null,
// wrong type, empty, malformed — must be a string in content-address form.
func contentAddressField(subject map[string]any, key string, required bool) error {
	raw, present := subject[key]
	if !present {
		if required {
			return fmt.Errorf("vc: wire form: %s is required", key)
		}
		return nil
	}
	s, ok := raw.(string)
	if !ok || !IsContentAddress(s) {
		return fmt.Errorf("vc: wire form: %s (%v) is not a sha256:<hex> content address", key, raw)
	}
	return nil
}

// IsContentAddress reports whether s is a content address in the canonical
// form "sha256:" followed by 64 lowercase hex characters — the grammar shared
// by previousCredential links, VC-resolver keys, and audit receipts' consumed
// sets. It is a pure syntax check; it asserts nothing about resolvability.
func IsContentAddress(s string) bool {
	const prefix = "sha256:"
	const hexLen = 64 // sha-256 is 32 bytes
	if len(s) != len(prefix)+hexLen || s[:len(prefix)] != prefix {
		return false
	}
	for _, r := range s[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// ValidateWireForm checks the receiver-side wire-form contract of the
// credential as one named operation: @context and claim grammar/grounding,
// the required VC types and fields, the raw wire shapes of the lossy
// optional fields, content-address syntax of the hash-valued fields, and
// source-commitment shape well-formedness. It performs no resolution and no
// signature verification — those belong to the confidence axes, and a nil
// error therefore never means "the credential verifies".
//
// This is the single implementation of the wire-form verdict: the verifier's
// data-integrity axis delegates to it as the resolution-free prerequisite it
// evaluates before its refinements (the cross-credential binding in
// VerifyChain, schema content-hash resolution), so a standalone caller and
// Verify can never disagree about well-formedness.
func (c *PipelinePassCredential) ValidateWireForm() error {
	if c == nil {
		return errors.New("vc: wire form: nil credential")
	}
	if c.Issuer() == "" {
		return errors.New("vc: wire form: issuer is missing")
	}
	if !hasRequiredVCTypes(c) {
		return errors.New("vc: wire form: type must carry VerifiableCredential and PipelinePassCredential")
	}
	// @context: credentials/v2 first, the dplaax protocol context present; a
	// profile may append extension contexts (credential.field.context).
	ctxList, ok := c.body[keyContext].([]any)
	if !ok || len(ctxList) == 0 || ctxList[0] != ContextCredentialsV2 {
		return errors.New("vc: wire form: @context must be an array with " + ContextCredentialsV2 + " first")
	}
	hasProtocolCtx := false
	for _, e := range ctxList {
		if e == ContextDplaaxVCV1 {
			hasProtocolCtx = true
			break
		}
	}
	if !hasProtocolCtx {
		return errors.New("vc: wire form: @context must contain the dplaax protocol context " + ContextDplaaxVCV1)
	}
	// validFrom is recommended, not mandatory (credential.field.valid-from):
	// absence is acceptable; a present value must be an RFC 3339 UTC timestamp
	// at second precision. time.Parse alone accepts zoned offsets and
	// fractional seconds, so both are rejected explicitly: a non-zero offset
	// is not UTC, and a fractional part violates second precision even when
	// it is all zeros. Go's parser admits both '.' and ',' as the fraction
	// separator (ISO 8601 leniency; RFC 3339's ABNF permits only '.'), and
	// neither character appears anywhere else in a parseable timestamp.
	// "-00:00" is RFC 3339 §4.3's unknown-local-offset form — an explicit
	// statement that the offset is NOT known, so it cannot assert UTC; the
	// parser folds it to offset 0 (indistinguishable from Z/+00:00 after
	// parse), so it is rejected at the string level (cred-032).
	if raw, present := c.body[keyValidFrom]; present {
		s, ok := raw.(string)
		if !ok {
			return errors.New("vc: wire form: validFrom must be a string")
		}
		parsed, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("vc: wire form: validFrom: %w", err)
		}
		if _, offset := parsed.Zone(); offset != 0 {
			return fmt.Errorf("vc: wire form: validFrom %q is not a UTC timestamp", s)
		}
		if strings.HasSuffix(s, "-00:00") {
			return fmt.Errorf("vc: wire form: validFrom %q carries the unknown-local-offset form (-00:00), not an asserted UTC", s)
		}
		if strings.ContainsAny(s, ".,") {
			return fmt.Errorf("vc: wire form: validFrom %q carries sub-second precision", s)
		}
	}
	rawSubject, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return errors.New("vc: wire form: credentialSubject must be an object")
	}
	// Raw wire-shape validation BEFORE the typed accessors — the typed views are
	// lossy (they drop present-but-wrong-typed fields to zero values), so a
	// malformed field would otherwise read as "absent" and slip through.
	if !rawSubjectWellFormed(rawSubject) {
		return errors.New("vc: wire form: credentialSubject carries a malformed optional field")
	}
	subj, err := c.Subject()
	if err != nil {
		return fmt.Errorf("vc: wire form: credentialSubject: %w", err)
	}
	if subj.PipelineID == "" || subj.ProcessID == "" {
		return errors.New("vc: wire form: pipelineId and processId are required")
	}
	// Content-address syntax on the RAW wire values — the typed view collapses
	// a present-but-wrong-typed or empty value to "", which must reject as
	// malformed, never skip as absent. outputHash is required; inputHash is
	// optional (on chain-preserving credentials the chain data-flow continuity
	// check enforces presence, and origins may legitimately omit it);
	// previousCredential is optional with JSON null equivalent to omission —
	// the only sanctioned non-string form among these
	// (credential.subject.previous-credential).
	if err := contentAddressField(rawSubject, keyOutputHash, true); err != nil {
		return err
	}
	if err := contentAddressField(rawSubject, keyInputHash, false); err != nil {
		return err
	}
	if raw, present := rawSubject[keyPreviousCredential]; present && raw != nil {
		s, _ := raw.(string) // rawSubjectWellFormed guaranteed the type
		if !IsContentAddress(s) {
			return fmt.Errorf("vc: wire form: previousCredential %q is not a sha256:<hex> content address", s)
		}
	}
	// Schema reference shape (credential.schema-ref): when the schema object is
	// present it must carry id, type, and a well-formed contentHash. Resolving
	// and comparing the hash against the registry is the axis refinement, not
	// wire form.
	if raw, present := rawSubject[keySchema]; present {
		ref, ok := raw.(map[string]any)
		if !ok {
			return errors.New("vc: wire form: schema must be an object")
		}
		id, _ := ref["id"].(string)
		typ, _ := ref["type"].(string)
		contentHash, _ := ref["contentHash"].(string)
		if id == "" || typ == "" || contentHash == "" {
			return errors.New("vc: wire form: schema must carry id, type, and contentHash")
		}
		if !IsContentAddress(contentHash) {
			return fmt.Errorf("vc: wire form: schema.contentHash %q is not a sha256:<hex> content address", contentHash)
		}
	}
	// Claim rules (presence, grammar, grounding) and the @context array shape.
	if err := c.ValidateTransformationClaim(); err != nil {
		return fmt.Errorf("vc: wire form: %w", err)
	}
	// Source-commitment value well-formedness — orthogonal to previousCredential,
	// so checked on any credential that carries the fields (raw type-shape was
	// validated above; this checks the sorted-unique set and multihash digest).
	if sc := c.SourceCommitment(); sc != nil {
		if !isSortedUniqueSet(sc.DerivedFrom) {
			return errors.New("vc: wire form: derived_from is not a duplicate-free ascending set")
		}
		if !isSourceRootMultihash(sc.SourceRoot) {
			return fmt.Errorf("vc: wire form: source_root %q is not an f1220 multihash digest", sc.SourceRoot)
		}
	}
	return nil
}
