# vcresolver — Provenance Chain Resolution

Stores VCs submitted by pipeline runtimes and resolves `previousCredential` chains
across registry boundaries for audit.

## Behaviour

- `StoreVC` stores a VC (keyed by JCS SHA-256 hash) and enqueues its
  `previousCredential` as unresolved if not already held.
- A background batch resolver periodically drains the unresolved pool, fetching VCs
  from their upstream registry endpoints (ConnectRPC), recursing the chain on success,
  with bounded retries and fallback to additional registries on connection errors only.
- Caller-supplied and document-derived upstream endpoints pass the SSRF guard before
  any outbound call.

## PoC posture

The production wiring (`cmd/network`) backs the VC store and unresolved pool
with the file-backed `vcfilestore` under the node's data-dir; the in-memory
implementations remain for tests and embedded use. All batch tuning parameters
come from `reference.conf` (no Go-side defaults; non-positive overrides fail
startup).

**Audit obligation**: the post-hoc audit model requires VC bodies to remain
resolvable for the audit horizon. The file-backed store satisfies this for a
single node; the transactional guarantees land on the `tlog`-backed substrate.
In-memory operation is acceptable for development only, never for deployments
that claim auditability.
