# resolver — DID Document Resolution

The `Resolver` interface (`Resolve(did string) (*did.DIDDocument, error)`) and its
implementations.

## Implementations

| Path | Status | Behaviour |
| --- | --- | --- |
| `local/` | implemented | In-memory store; tests and fixtures |
| `cache/` | implemented | TTL/byte-bounded caching decorator (`Resolver`) |
| `grpc/` | planned | ConnectRPC call to a registry's DIDService |
| `multi/` | planned | Home-registry-first, fallback to additional registries |

`local/` and `cache/` are present in this module today. The `grpc/` and
`multi/` rows — and their Conventions below — describe their intended
contract.

## Conventions

- `cache/` caches successful resolutions only, expires entries a fixed TTL
  after the fill (hits never refresh), returns a freshly parsed document per
  hit (no shared `*did.DIDDocument`), and never converts a successful
  resolution into an error — an uncacheable document is served uncached. Both
  an entry-count and a byte bound are mandatory: resolution keys arrive from
  unauthenticated input. See the package comment for the freshness/threat
  discussion.
- `grpc/` validates that the returned document ID equals the requested DID
  (registry-substitution defense).
- `multi/` fallback fires on **connection errors only**. Application errors
  (not-found, permission) from any registry are authoritative and short-circuit —
  fallback must never mask a configuration error on the negative path.
- Home URL derives from the DID's `registry` segment (`https://{registry}`);
  overridable via a default-registry escape hatch or an explicit segment→URL map
  (compose / multi-registry dev).
