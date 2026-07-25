# delegation — Delegation Credentials

Owner-signed `DelegationCredential` asserting that an Owner DID delegates authority
to a Pipeline or Process DID. The provin profile is **unscoped**: a delegation
carrying a scope is rejected fail-closed (the spec's `delegation.scope` keeps
scope optional for other wire profiles; provin opts out — see `delegation.go`).

## Conventions

- Issuer must equal `delegatedBy`; verification resolves the issuer's DID Document and
  checks the proof against the owner's assertion key.
- Delegation credentials are persisted alongside the delegated DID by the registry and
  served via `ResolveDelegation`.
- Proof mechanics are reused from `vc` (`CreateProof` / `VerifyProof`) —
  this package owns only the delegation-specific shape and rules.
