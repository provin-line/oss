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
- `NewVerifier(url, opts…) (endpoint.VerifierEndpoint, error)` — builds the
  production verifier (the `auth.policy-verifier` REST client). The URL must carry
  an explicit `http://`/`https://` scheme (fail-closed; no accidental plaintext).
  Tests use `endpoint.NewStaticEndpoint` directly.
- `AuthConfig` + `LoadAuthConfig` — the typed `provin.network.auth.*` config
  (`policy-verifier-url`), validated fail-closed at boot (empty/scheme-less → boot
  error, so authorization is never run against an unset endpoint).

## Policy declaration

Authorization policy is declared per-RPC in the `.proto` via the
`o3co.authz.v1.policy` method option (`resource` + `action`, optional
`field_mappings`). **An RPC with no option is not checked** — a descriptor test
asserts every protected service annotates all its RPCs, so an unprotected RPC
fails the build rather than shipping open.

`ChainPeerService` is intentionally NOT enforced here — it authenticates at L2
(wireauth), never L1.
