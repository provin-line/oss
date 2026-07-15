package vc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/provin-line/oss/canon/jcs"
)

// The WireVariantID grammar (spec: identity.wire-variant-id), split into the
// parts it deliberately pins so a reader can see what changing one would cost.
//
// A body address answers "which document"; a variant id answers "which
// SIGNED FORM of that document" — one body can hold several, since re-issuing
// a proof leaves the body (and therefore every successor link) untouched.
const (
	// wireVariantPrefix pins, in order: the id version (v1), the
	// canonicalization profile the digest is taken over, and the hash
	// algorithm. A reader never has to infer any of the three from context,
	// and a future profile cannot silently reuse this id space — it would
	// have to spell a different prefix, which the catalog freezes.
	wireVariantPrefix = "wire:v1:" + jcs.NameRFC8785 + ":sha256:"

	// wireVariantDomainTag separates this digest from every other sha256 in
	// the protocol (body addresses, source roots, checkpoints). Without it,
	// bytes that are a valid document in one role could carry a digest
	// meaningful in another; with it, no input can produce a colliding id
	// across roles. The NUL is the terminator: it cannot occur in the
	// canonical JSON that follows, so tag and payload cannot be confused for
	// each other by any choice of document.
	wireVariantDomainTag = "provin-wire-variant-v1\x00"

	wireVariantHexLen = 64 // sha-256 is 32 bytes
)

// WireVariantID returns this credential's variant id — "wire:v1:jcs-rfc8785:
// sha256:<hex>" over the domain tag followed by the RFC 8785 canonical bytes
// of the FULL wire document, proof included (spec: identity.wire-variant-id).
//
// The digest is over the canonical PROJECTION, not the octets a submission
// arrived in: two peers that spell the same document differently (key order,
// whitespace, escape forms) admit it under one id, and re-spelling cannot
// mint a second identity for one signed form. That is also why the id is
// derived rather than accepted from a caller — the bytes decide it.
//
// The type does not preclude a future independent proof-envelope id
// (identity.proof-envelope.not-claimed): that would be its own id space, not
// a reinterpretation of this one.
func (c *PipelinePassCredential) WireVariantID() (string, error) {
	wire, err := c.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("vc: wire variant id: canonicalize wire document: %w", err)
	}
	return WireVariantIDOf(wire), nil
}

// WireVariantIDOf returns the variant id of ALREADY-CANONICAL wire bytes.
//
// It is the seam for callers holding stored bytes rather than a decoded
// credential (a store validating what it read back). It assumes what its name
// says: bytes that are not the canonical projection get an id no fetch will
// ever ask for, so a caller that cannot vouch for canonicality must compare
// against the projection itself rather than trust this id
// (identity.variant.immutable-set: re-spelled bytes are corruption at an id,
// not an encoding of it).
func WireVariantIDOf(canonicalWire []byte) string {
	h := sha256.New()
	h.Write([]byte(wireVariantDomainTag))
	h.Write(canonicalWire)
	return wireVariantPrefix + hex.EncodeToString(h.Sum(nil))
}

// IsWireVariantID reports whether s is a wire variant id in the canonical
// form "wire:v1:jcs-rfc8785:sha256:" followed by 64 lowercase hex characters.
// It is a pure syntax check: it asserts nothing about whether the variant is
// held, valid, or verified.
func IsWireVariantID(s string) bool {
	_, ok := WireVariantHex(s)
	return ok
}

// WireVariantHex returns the hex payload of a well-formed variant id, and
// whether s was one.
//
// It exists so a storage layer can name what it holds without re-implementing
// this grammar: the payload is hex, so it is safe as a file name or map key by
// construction, and a backend that never learns the prefix cannot drift from
// it when the canonicalization profile moves. IsWireVariantID is this
// function's answer with the payload dropped — one parser, so a string cannot
// be valid to one caller and malformed to another.
func WireVariantHex(s string) (string, bool) {
	if len(s) != len(wireVariantPrefix)+wireVariantHexLen || s[:len(wireVariantPrefix)] != wireVariantPrefix {
		return "", false
	}
	hexPart := s[len(wireVariantPrefix):]
	if !isLowerHex(hexPart) {
		return "", false
	}
	return hexPart, true
}

// WireVariantIDFromHex is WireVariantHex's inverse: it re-attaches the prefix
// to a hex payload a backend named. It does not validate — a caller holding a
// payload that did not come from WireVariantHex is already lost.
func WireVariantIDFromHex(hexPart string) string { return wireVariantPrefix + hexPart }

// isLowerHex reports whether s is entirely lowercase hexadecimal. Uppercase
// is rejected rather than folded: an id is compared as a string (it is a map
// key and a file name), so admitting two spellings of one digest would admit
// two identities for one variant.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
