# signer — KMS-Model Signing Service

Ed25519 signing backed by `keystore`. Private keys never leave the registry
process; pipeline processes and peers hold DIDs, not keys.

Two signing modes, two consumers:

| RPC | Input | Output | Used by |
|---|---|---|---|
| `Sign` | `sha256:<hex>` pre-hash | base58btc (`z`-multibase) signature | VC proof creation (pipeline provenance) |
| `SignRaw` | raw bytes | raw 64-byte signature | L2 wire-signing (chainmanager wireauth) |

Key lookup is by DID + logical key ID (`auth` → `#auth`, `signing` →
`#signing`). The chainmanager depends on this service through a narrowed
interface defined on the consumer side — never on the package itself (avoids
service-to-service import cycles).
