package contract

import (
	"context"
	"fmt"
)

// PayloadDelivery is the agreed payload-delivery mode of a consuming ingress.
// It is negotiated per subscription and immutable for the subscription's
// lifetime (see the Envelope contract and the chainmanager Subscription
// record). The runtime uses it to decide, decisively, what a present or absent
// envelope payload means — a mode mismatch is a protocol violation, not a
// silent fallback.
//
// The zero value is DeliveryInline: in-org producing processes always emit the
// full inline envelope, so a loop that says nothing about delivery expects
// inline bytes. By-reference is opted into only where a cross-org ingress is
// wired to a by-reference subscription.
type PayloadDelivery int

const (
	// DeliveryInline — the envelope carries the payload bytes inline. A nil
	// payload under this mode is a decidable protocol violation (payload
	// stripped in error).
	DeliveryInline PayloadDelivery = iota
	// DeliveryByReference — the envelope carries no payload; the consumer
	// dereferences it from the publisher's serving boundary by content hash. A
	// present payload under this mode is a decidable protocol violation (an
	// export-seam misconfiguration that may leak a confidential payload).
	DeliveryByReference
)

// ParsePayloadDelivery maps the wire/config mode string to a PayloadDelivery.
// The empty string is the by-reference default (matching the chain.v1
// negotiation default), while an explicit "inline" selects inline. An
// unrecognized value is an error — a delivery mode is never guessed.
//
// Note the asymmetry with the zero value: the config surface defaults an
// UNSET field to inline (in-org expectation), whereas an explicitly EMPTY
// negotiated mode string means by-reference. The two defaults live at
// different layers on purpose; callers pass the value they actually hold.
func ParsePayloadDelivery(s string) (PayloadDelivery, error) {
	switch s {
	case "", "by-reference":
		return DeliveryByReference, nil
	case "inline":
		return DeliveryInline, nil
	default:
		return DeliveryInline, fmt.Errorf("contract: unknown payload-delivery mode %q (want \"inline\" or \"by-reference\")", s)
	}
}

// String renders the mode as its canonical wire/config token.
func (d PayloadDelivery) String() string {
	switch d {
	case DeliveryInline:
		return "inline"
	case DeliveryByReference:
		return "by-reference"
	default:
		return fmt.Sprintf("PayloadDelivery(%d)", int(d))
	}
}

// PayloadResolver dereferences a by-reference payload: it returns the payload
// bytes stored at contentHash ("sha256:<hex>") on the publisher's serving
// boundary at upstreamEndpoint.
//
// The resolver makes NO trust claim about the returned bytes — the caller's
// payload↔credential binding gate (sha256(payload) == the predecessor's
// declared outputHash) is the sole integrity check, exactly as for inline
// delivery. A resolver that returns bytes hashing to something other than what
// the caller asked for still passes nothing: the binding gate rejects them.
//
// Resolution failure is a LIVENESS failure of the event (the runtime rejects /
// errors / drops per its own failure model), never a confidence verdict: the
// payload is transformation material, not verification evidence, so a fetch
// miss must not refine any confidence axis. The runtime does not distinguish a
// definitive miss from a transient error (both stop the event); a resolver
// implementation MAY surface its own sentinel for observability (e.g. the
// network client's ErrNotFound).
type PayloadResolver interface {
	ResolvePayload(ctx context.Context, upstreamEndpoint, contentHash string) ([]byte, error)
}
