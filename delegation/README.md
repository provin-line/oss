# delegation — Delegation Credentials

Owner-signed `DelegationCredential` asserting that an Owner DID delegates authority
(scoped, e.g. `pipeline:operate`, `process:sign`) to a Pipeline or Process DID.

## Conventions

- Issuer must equal `delegatedBy`; verification resolves the issuer's DID Document and
  checks the proof against the owner's assertion key.
- Delegation credentials are persisted alongside the delegated DID by the registry and
  served via `ResolveDelegation`.
- Proof mechanics are reused from `vc` (`CreateProof` / `VerifyProof`) —
  this package owns only the delegation-specific shape and rules.
