# network/pkg/auth — L1 Authorization Enforcement (PEP)

The network layer's authorization **enforcement point**. It does not decide
policy or issue tokens; it wires the existing
[`o3co/protobuf.interceptors`](https://github.com/o3co/protobuf.interceptors)
ConnectRPC interceptors and a configured verifier onto the services' handlers.

Three-layer separation (the dPLaaX auth stack):

| Layer | Where | Role |
|---|---|---|
| Token issuance (authN) | `o3co/auth.provider` + provin.auth provider | DID-grant OAuth; issues a no-scope identity JWT (`sub` = Owner DID) |
| Decision (authz) | `o3co/auth.policy-verifier` + provin.auth `policy-verifier-dplaax-module` | the PDP; rule/attribute collectors keyed on `{resource, action}`, DID-aware |
| **Enforcement (authz)** | **this package** | the PEP — reads the proto policy option, calls the PDP, allows/denies |

## What it provides

- `Interceptors(verifier) []connect.Interceptor` — the ordered chain
  (`PolicyOptionInterceptor` then `VerificationInterceptor`) to mount on a
  handler. Order is fixed: the option interceptor populates context before the
  verification interceptor reads it.
- `NewVerifier(cfg) (Verifier, error)` — builds the production verifier for the
  configured backend (`o3co` | `opa` | `cedar` | `static`). The URL must carry an
  explicit `http://`/`https://` scheme (fail-closed). Plaintext to a non-loopback
  host is refused unless its `host:port` is listed in
  `provin.network.auth.plain-internal`; `With*AllowInsecure` is never used.
- `AuthConfig` + `LoadAuthConfig` — the typed `provin.network.auth.*` config,
  validated fail-closed at boot (empty/scheme-less URL, or a missing/contradictory
  `cedar.jwt.*` block under `backend = "cedar"` → boot error).
- The `cedar` backend verifies the bearer JWT itself (a Cedar agent authenticates
  nothing): `cedar.jwt.issuer`, `cedar.jwt.audience` and exactly one of
  `cedar.jwt.jwks-url` (https) / `cedar.jwt.secret` (HS256, `cedar.jwt.secret-encoding`
  `utf8` | `hex` | `base64`). The verification lives in the internal
  `jwtprincipal` package behind a one-method interface; this package only selects
  the backend and passes the resolver in.

## Policy declaration

Authorization policy is declared per-RPC in the `.proto` via the
`o3co.authz.v1.policy` method option (`resource` + `action`, optional
`field_mappings`). **An RPC with no option is not checked** — a descriptor test
asserts every protected service annotates all its RPCs, so an unprotected RPC
fails the build rather than shipping open.

`ChainPeerService` is intentionally NOT enforced here — it authenticates at L2
(wireauth), never L1.
