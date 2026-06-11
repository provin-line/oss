# resolver — DID Document Resolution

The `Resolver` interface (`Resolve(did string) (*did.DIDDocument, error)`) and its
implementations.

## Implementations

| Path | Behaviour |
|---|---|
| `local/` | In-memory store; tests and fixtures |
| `grpc/` | ConnectRPC call to a registry's DIDService |
| `multi/` | Home-registry-first with fallback to additional registries |

## Conventions

- `grpc/` validates that the returned document ID equals the requested DID
  (registry-substitution defense).
- `multi/` fallback fires on **connection errors only**. Application errors
  (not-found, permission) from any registry are authoritative and short-circuit —
  fallback must never mask a configuration error on the negative path.
- Home URL derives from the DID's `registry` segment (`https://{registry}`);
  overridable via a default-registry escape hatch or an explicit segment→URL map
  (compose / multi-registry dev).
