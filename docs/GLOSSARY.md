# Glossary

Definitions are **responsibility-based**: each entry states what a term *is* and what
it guarantees, never current implementation values (catalogs, counts, algorithm
choices, wire literals). For concrete values, read the package contracts and the
dPLaaX spec — they are the source of truth and this file must not drift with them.

## Protocol & naming

**dPLaaX** — The protocol this repository implements: every data transformation is
attested as a signed credential, forming a verifiable provenance chain. The protocol
owns the wire namespace (proto packages, DID method, the protocol JSON-LD context); it is
implementation-independent.

**provin** — The product: the reference *wire profile* of dPLaaX maintained in this
repository. The name appears in deliverables (repository, CLI, images) and in the
profile's extension namespace, never in the protocol's wire namespace.

**wire profile** — The declaration layer between the dPLaaX wire spec and a concrete
implementation. A profile declares which protocol catalogs it adopts, may narrow or
tighten protocol defaults, and may add namespace-prefixed extensions; where the
protocol pins only grammar (transformationClaim), the profile owns the semantics
outright. It must not contradict protocol-normative rules.

## Credential & chain

**PipelinePassCredential (PPC)** — The single credential type of the pipeline layer:
a Verifiable Credential attesting that one process boundary consumed an input and
produced an output. The subject carries content hashes and declarations, never the
payload itself.

**provenance chain** — The strictly linear sequence of PPCs linked through
`previousCredential`. Each link has exactly zero or one predecessor; lineage that is
not expressible as a linear chain is handled at origin boundaries, not by branching
the chain.

**content commitment** — Referencing an artifact by a cryptographic hash of its
canonical byte form rather than by a name or locator. Chain links use content
commitments so that long-horizon audits do not depend on any registry surviving.

**previousCredential** — The chain link field of a PPC: a content commitment to the
predecessor credential. Its absence marks the credential as a FirstDrop.

**FirstDrop** — A PPC with no predecessor: the origin of a chain and the deliberate
trust boundary of the model. A FirstDrop attests *who emitted which bytes under which
schema*; it makes no claim about the world before ingestion.

**trigger rule** — The normative criterion deciding chain topology: a boundary is
chain-preserving exactly when its execution was triggered by the arrival of a single
conformant predecessor event; any other trigger yields a FirstDrop.

**data-flow invariant** — The guarantee that each credential's output hash equals its
successor's input hash, letting a verifier prove byte-level continuity across the
chain without re-reading payloads.

**payload** — The actual data flowing through the pipeline. Payloads are bound to
credentials by hash and are integrity-protected, but never embedded in, recoverable
from, or interpreted by the credential layer.

**payload delivery mode** — The per-subscription agreed choice of how payload
bytes travel: *inline* (bytes ride in the envelope) or *by-reference* (hash-only
envelope; the subscriber fetches bytes from the publisher's serving boundary by
content hash, and provenance-only consumers never fetch). Negotiated at
registration, immutable per subscription, defaulting to by-reference.
Verification is independent of the mode — the hash binding makes the bytes
provable wherever they came from.

**transformationClaim** — The boundary's claim about the output's information
source: whether the declared inputs are the output's complete information source
(closed-world — absence from the declared set licenses an exclusion inference) or
not. The protocol pins only the grammar (a single namespace-prefixed token) and the
open-world default (no closed-world inference from unrecognized claims); the
semantics are pinned per claim by the profile (`vc.TransformationClaim` registry).
Claim identity is the (grounding URL, label) pair: the namespace prefix must be
grounded by a context in @context, so an impostor prefix is byte-distinguishable
inside the signing scope. It is a declaration by the signer, not a machine-verified
property — its audit value is accountability for the claim. Claims do not bind
chain topology.

**SchemaRef** — A content-committed reference to the registered schema of the output,
making retroactive schema modification cryptographically detectable.

**SourceCommitment** — An optional attestation, on any credential, committing to the
full set of conformant source credentials the boundary consumed (on a
chain-preserving credential this includes the triggering predecessor — all-consumed
semantics). It records *audit attributes*, not parent links: the chain stays linear,
and reads from the outside world are deliberately out of its scope.

**source_root** — The Merkle set commitment inside a SourceCommitment: a compact,
order-independent commitment to the consumed source credentials, supporting
per-source inclusion proofs.

**audit-reachable** — The conformance class in which source commitments are emitted
and verified ingress credentials are retained, so that dataset-level lineage can be
audited after the fact.

**boundary translation** — Ingesting a credential from an external ecosystem by
re-signing its content as a dPLaaX FirstDrop. The external credential's own
verification is attested at ingestion; it does not extend the chain backwards.

**DID method tiers (T1/T2/T3)** — Documentation vocabulary for what a DID
method's resolution can prove over time. T1 = `did:dplaax` (federation-governed
registry, append-only lifecycle records, organization verification) — the only
method admitted on the credential-issuance plane. T2 = `did:webvh` / `did:tdw`
(self-hosted, tamper-evident key history) — retrospectively verifiable.
T3 = `did:web` (current-state document, no history) — sufficient only
point-in-time. The tiers inform deployment policy on the authentication plane
and qualify the evidence strength of external-DID-source ingestion; they are
a vocabulary, not a type-level contract.

**enrichment** — A chain-preserving boundary that joins side-fetched external data
onto the event that triggered it.

**aggregation** — Folding a pooled set of inputs into one output. The output is a
FirstDrop because the run is not triggered by a single conformant event (trigger
rule); that the result has no identity relationship with any single input is the
rationale, not the criterion.

## Components

**Pipeline Component** — A peer participating in a pipeline. Component types form a
catalog of *definitional properties*; no type is privileged and pipelines are free
graph compositions of them.

**FilterConvert** — The component type defined by stateless per-event transformation:
one conformant input event in, one output out, chain preserved.

**Origin Source** — The component type defined by emitting FirstDrops: it is where
data enters the provenance model, whether by external ingestion, aggregation, or
generation-like derivations.

**External Sink** — The component type defined by terminating the chain: it consumes
verified data and surfaces it (with its verification verdict) to the outside world.

**Custom** — The component type defined by conforming to the Pipeline Contract on at
least one I/O side while not fitting the other catalog definitions.

**Pipeline Contract** — The interface obligations a component must satisfy to
participate: how it verifies ingress, what it must attest on egress, and what it must
retain for audit.

**IngressVCStore** — The retention obligation attached to verification: a component
that verifies ingress credentials must persist them, because verifying without
storing breaks chain audits.

## Identity & trust

**did:dplaax** — The protocol's DID method. The registry operating a DID is named
inside the identifier, so environment and operator are part of identity rather than
out-of-band knowledge.

**Owner DID / Pipeline DID / Process DID** — The identity hierarchy: an Owner
(accountable organization) controls Pipelines (deployed flows), which control
Processes (signing boundaries). Credentials are signed at the Process level;
accountability is resolved upward through the hierarchy.

**Owner identity binding (`alsoKnownAs`)** — The pattern for stating that a
did:dplaax Owner and an organization's outward identity (e.g. `did:web`) are the
same party. Verifiable only **bidirectionally** — each DID document names the
other, a state only the controller of both key sets can produce — and even then
it proves key co-control, not legal identity; the authoritative
Owner-to-legal-entity binding is the federation registry's organization
verification (T1). The binding is **point-in-time**: it asserts co-control at
the moment of resolution. Relying parties therefore snapshot what they relied
on (as with L2 registration), auditors compare the current web-side document
against the registry-witnessed snapshot to detect domain takeover, and
audit-sensitive deployments prefer T2 methods whose verifiable key history
makes continuity checkable. The binding **never moves attribution**:
responsibility is computed against the did:dplaax Owner (`audit.attribution.*`)
regardless of any alias, so a lost or hijacked domain is bounded to the alias
and authentication layer. There is no equivalence registry; rotation and loss
are lifecycle events recorded append-only on the dplaax side.

**DelegationCredential** — An owner-signed credential asserting that scoped authority
was delegated down the identity hierarchy, letting a verifier reconstruct the
controller chain behind a signature.

**Data Integrity proof** — The W3C proof form used to sign credentials: the proof is
attached outside the signed scope and names the cryptosuite and verification method
used.

**cryptosuite** — A named, versioned combination of canonicalization and signature
scheme. Suites have an explicit lifecycle evaluated at proof-creation time, so
verification outcomes degrade predictably as suites age; unknown or no-op suites fail
closed.

**canonicalization** — The deterministic byte form a document is reduced to before
hashing or signing, so that semantically equal documents commit to equal bytes.

**confidence** — The verification result semantics of a chain: per-axis verdicts are
combined by weakest link, and inability to verify is distinguished from proven
failure.

**organization verification** — Out-of-band endorsement binding a DID to a real-world
operator (e.g., a DNS record under the operator's domain). It is orthogonal to
credential confidence: it changes who you believe a signer is, not whether the chain
verifies.

**transparency log** — An optional append-only log layer providing inclusion and
consistency proofs over issued artifacts, strengthening audits against retroactive
substitution by the issuer or registry.
