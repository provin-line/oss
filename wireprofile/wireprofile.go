// Package wireprofile pins wire-level conventions shared across deployment
// roots. network/ and pipeline/ never import each other (AGENTS.md rule 2);
// constants both sides must agree on live here instead. wireprofile is a
// leaf: it imports nothing from gen/, network/, pipeline/, or cmd/, so
// either tree can depend on it without violating the layer rule.
package wireprofile

// ByReferenceSubjectPrefix is the wire subject prefix a by-reference-mode
// export carries (D-2): "byref." + publisherDID. Prefix, not suffix, is the
// structurally collision-free choice — a producing loop's output subject is
// always a dplaax pipeline DID (config-loader enforced, always starts with
// "did:"), and a dplaax DID's registry segment may itself contain dots
// (e.g. "poc.dplaax.dev"), so a suffix scheme ("<DID>.byref") cannot rule out
// colliding with a DID that happens to end in a ".byref" segment without a
// grammar proof. A prefix partitions cleanly: the first token is either
// "byref" or "did:...", never both.
//
// This is the ONE definition. network/'s
// chainmanager.ByReferenceSubjectPrefix is a const alias of this value —
// see network/pkg/services/chainmanager/subject.go — so a future pipeline/
// consumer can import it here without network/ and pipeline/ importing each
// other.
const ByReferenceSubjectPrefix = "byref."
