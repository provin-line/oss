# Audit Record Obligations

The post-hoc audit model attributes responsibility by reconciling records that
parties cannot edit or deny. This page consolidates **which records the provin
profile obligates, who holds each one, and where each obligation is enforced**.
The obligations are scattered across the seams that enforce them by design;
this page is the index, not a second source of truth.

## The three record obligations

| Record | Content | Holder | Enforcing seam |
|---|---|---|---|
| Emission log | Every published event: credential hash + sequence number, append-only | Publisher | `pipeline/transport` (publisher loop) on the `tlog` substrate |
| Subscription record | The subscriber's L2-signed `RegisterSubscription` view, including the agreed payload-delivery mode | **Publisher** (adversarial holding — the record works against the subscriber) | `network/.../chainmanager` (`store/`) |
| Ingress store | Verified ingress credentials, retained | Subscriber | `network/.../vcresolver` store (pairs with the audit-reachable conformance class) |

Each record is held by a party it can be used *against*, or is append-only —
so "I never subscribed", "you never sent it", and "I never received it" all
reconcile against records the denier cannot rewrite. Sequence numbers make
emission gaps evidence rather than glitches; the emission identity is
delivery-form-independent (the same event yields the same record whether
delivered inline or by reference).

**Retention** for the audit horizon is a deployment obligation — the profile
pins what must be recorded and its tamper-evidence, not how long a given
deployment's regulators require it kept.

## Where the protocol floor ends and these obligations begin

The dPLaaX protocol itself guarantees the audit *floor*: chain topology, the
data-flow invariant, source commitments (audit-reachable class), and the
responsibility-attribution rules (`audit.attribution.*` — per-segment
attribution to the issuer's Owner, and the unconditional origin default).
Those hold for any conformant implementation.

The record obligations on this page are deliberately **profile-level** (split
decided 2026-06-11): normalizing them in the protocol would import
publisher/subscriber vocabulary into a transport-agnostic wire spec. If a
second implementation needs cross-implementation audit interop, the promotion
path is a transfer-relationship abstraction added to the protocol as a 0.x
minor.

## Substrate

All three records persist on `tlog` — per-organization, append-only,
tamper-evident logs with a production-grade contract (signed checkpoints,
optional inclusion/consistency proofs) and staged implementations. No
network-global log exists; each organization hosts its own records under its
own DID.
