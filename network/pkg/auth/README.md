# network/pkg/auth — L1 Authentication & Authorization

Bearer-JWT verification and RBAC enforcement for operator-facing RPCs.

- `JWTVerifier` interface with two implementations: JWKS (Ed25519, issuer-fetched,
  cached) and HS256 (shared secret). Mode selected by config; "none" is permitted
  only for local development.
- The Connect interceptor extracts the token, verifies it, and stores the subject in
  context; per-RPC enforcement reads the policy options declared in the proto.
- **ChainPeerService routes are intentionally absent from L1 rules** — they are
  authenticated exclusively at L2 (wireauth). Adding them here would be a bug, not
  hardening: it would break cross-organization peering behind a misleading layer of
  apparent security.
- **Token issuance is not this package's job.** L1 tokens are issued by the external
  provin.auth service (separate repository; lineage: dplaasio/auth on the
  o3co.auth.provider stack) via the DID grant
  `urn:dplaax:oauth:grant-type:did` — the client proves control of an Owner DID and
  receives an identity-assertion JWT (`sub` = Owner DID, no scope). This package only
  verifies those tokens (JWKS) and enforces per-RPC policy.
