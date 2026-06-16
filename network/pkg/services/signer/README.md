# signer — KMS-Model Signing Service

Ed25519 signing backed by `keystore`. Private keys never cross the RPC boundary:
pipeline processes and peers hold DIDs, not keys; the registry process holds the
key material and returns only the signature.

Proto: `dplaax.signer.v1` (`SignerService`).

Two signing domains, two consumers:

| RPC | Input | Output | Key | Authz | Used by |
|---|---|---|---|---|---|
| `Sign` | raw bytes | raw Ed25519 signature | `#signing` | `signer:sign-vc` | VC proof creation (pipeline provenance) |
| `SignRaw` | raw bytes | raw 64-byte Ed25519 signature | `#auth` | `signer:sign-wire` | L2 wire-signing (chainmanager wireauth) |

## Raw-bytes seam

Both RPCs are a thin transport of the committed `crypto.Signer` seam: they take
the **raw** bytes to sign and return the **raw** Ed25519 signature. Output
encoding is the caller's concern — `vc.CreateProof` passes its proof `hashData`
and applies the base58btc multibase framing to the returned signature itself, and
L2 wire-signing uses the raw 64-byte signature directly. The service does not
re-frame the input as a `sha256:<hex>` prehash or the output as multibase; doing
so would force a pointless decode round-trip on the client.

## Two RPCs, two domains

`Sign` and `SignRaw` are cryptographically identical (Ed25519 over the supplied
bytes). They are split so the two signing domains carry **distinct authorization
policies** (an operator can grant VC-signing without granting wire-signing) and so
each **binds to its key relationship**: `Sign` accepts only `key_id == "signing"`
(the `#signing` assertionMethod key), `SignRaw` only `key_id == "auth"` (the
`#auth` authentication key). A crossed `key_id` is rejected — you cannot use the
VC endpoint to sign with the auth key, or vice versa.

## Consuming it

The production `crypto.Signer` is `client.New(SignerServiceClient)` — it dispatches
by keyID (the inverse of the server binding: `signing` → `Sign`, `auth` →
`SignRaw`) and returns the raw signature. A consumer (pipeline runtime, chainmanager
wireauth) depends on the service through that adapter / a narrowed consumer-side
interface — never on the service package itself (avoids service-to-service import
cycles). The `client` package imports only the generated client, `crypto`, and the
`keystore` key-ID contract.

## Deployment pattern, not protocol mandate

Fronting the signing seam with this network service is the **KMS deployment
pattern** (keys centralized in the registry). A single-process deployment may sign
**inline** instead (`crypto/ed25519.NewSigner` over local keys) and never expose
SignerService, and still produce protocol-valid proofs. provin's reference
deployment commits to the KMS pattern; the proto standardizes the wire shape *if*
you run one.
