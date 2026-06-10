# cmd/provin — Operator CLI

The `provin` CLI: operator tooling for DID, schema, and chain management against a
dplaax registry.

## Surface (planned)

| Command group | Operations | Backend |
|---|---|---|
| `owner` | init (local keygen + self-signed registration) | DIDService |
| `pipeline` | create (delegation-signed issuance) | DIDService |
| `process` | create (delegation-signed issuance) | DIDService |
| `schema` | register | SchemaService |
| `chain` | subscribe, set-allow | ChainService |
| `org` | verify / inspect / diagnose / generate-txt | DNS + DID resolution (no registry mutation) |

Global flags: `--registry` (env `PROVIN_REGISTRY`), `--token` (env `PROVIN_TOKEN`).

## Conventions

- `internal/client/` — ConnectRPC client construction + bearer-token interceptor +
  proto ↔ domain conversion. `internal/commands/` — one file per command group;
  commands hold no protocol logic beyond request shaping.
- Owner private keys are generated locally and stored as JWK files; they are the only
  private keys that ever exist outside the registry (everything else is KMS-model).
- Exit codes are meaningful for scripting (`org verify` maps verdict levels to codes).
