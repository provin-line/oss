package chainmanager

import (
	"errors"
	"fmt"
	"strings"
)

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
// Exported so the composition root (cmd/standalone) can bind a producing
// loop's dual-emit stripped-form publish to the EXACT subject this package
// will export for that loop's output under a by-reference subscription
// (subjectForMode) — the two must never drift independently.
const ByReferenceSubjectPrefix = "byref."

// ErrUnsafeSubject is returned when a publisher DID contains characters that
// are unsafe as a NATS subject — whitespace, the wildcard tokens `*` / `>`,
// or an empty dot-separated segment (leading/trailing/doubled dot) — or is
// empty. requirePipelineDID only proves "this parses as a dplaax pipeline
// DID"; NATS subject safety is a distinct, independently-enforced property,
// checked here at the one place that turns a publisher DID into a wire
// subject.
var ErrUnsafeSubject = errors.New("chainmanager: publisher DID is not a safe NATS subject")

// subjectForMode maps a subscription's AGREED payload-delivery mode to the
// wire subject chainmanager exports (publisher side) / imports-then-renames
// (subscriber side, see importTargets/Subscribe) for it: inline rides the
// publisher's plain pipeline DID unchanged; by-reference rides the
// ByReferenceSubjectPrefix-prefixed form (D-2). It doubles as the shared
// NATS-subject-safety validator for publisherDID (D-3) — every caller that
// turns a publisher DID into an exported/imported subject goes through this
// function, so a DID that is unsafe as a NATS subject fails closed with
// ErrUnsafeSubject for EITHER mode, never silently exported.
//
// mode is expected to already be one of "inline" / "by-reference" (the
// negotiated/stored form — see negotiatePayloadMode); any other value maps
// like "inline" (the conservative default: never widen exposure for an
// unrecognized mode).
func subjectForMode(publisherDID, mode string) (string, error) {
	if err := validateSubjectSafe(publisherDID); err != nil {
		return "", err
	}
	if mode == "by-reference" {
		return ByReferenceSubjectPrefix + publisherDID, nil
	}
	return publisherDID, nil
}

// validateSubjectSafe rejects an empty subject, one containing whitespace or
// a NATS wildcard token (`*` / `>`), or one with an empty dot-separated
// segment (leading/trailing/doubled dot, e.g. ".a", "a.", "a..b") — all
// structurally invalid or dangerously ambiguous as a literal (non-wildcard)
// NATS publish/export subject.
func validateSubjectSafe(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty subject", ErrUnsafeSubject)
	}
	if strings.ContainsAny(s, " \t\r\n*>") {
		return fmt.Errorf("%w: %q contains whitespace or a wildcard token", ErrUnsafeSubject, s)
	}
	for _, tok := range strings.Split(s, ".") {
		if tok == "" {
			return fmt.Errorf("%w: %q has an empty token", ErrUnsafeSubject, s)
		}
	}
	return nil
}
