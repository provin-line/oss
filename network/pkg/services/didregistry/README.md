# didregistry — DID Lifecycle Service

Issues and manages `did:dplaax` Owner, Pipeline, and Process DIDs.

## Rules

- **Every write proves authority cryptographically.** Owner registration verifies a
  self-signed Data Integrity proof (solves bootstrap — no prior account needed);
  pipeline/process issuance additionally verifies an owner-signed delegation
  credential (`delegation`).
- On pipeline/process issuance the service generates the `#auth-key` /
  `#signing-key` Ed25519 pair and persists it via `keystore` — callers never
  see private keys.
- Issued DID Documents embed service endpoints (`#vc-resolver`, etc.) from config.
- Key rotation grace semantics: verify-grace keeps the old public key resolvable for
  a window; there is no sign-grace by design (the KMS model stops old-key signing
  immediately).
- **Owner lifecycle is audit evidence.** Owner registration and outward-identity
  binding events (addition, rotation, loss — see Owner identity binding in the
  glossary) carry a snapshot of the resolved outward DID document and belong in an
  append-only lifecycle log. The yamlstore is the staged PoC substrate; tlog is the
  target.

## Storage

`store/` defines the DID document store interface; `store/yamlstore/` maps the DID
hierarchy to a directory tree (`{accountType}/{accountId}/pipelines/{id}/processes/{id}`)
with per-record YAML files. Private keys go through `keystore`, not this store.
