# cmd/provin — Operator CLI

The `provin` CLI: operator tooling for DID, schema, and chain management against a
dplaax registry.

## Surface

| Command group | Operations | Backend | Status |
| --- | --- | --- | --- |
| `owner` | init (local keygen + self-signed registration) | DIDService | implemented |
| `pipeline` | create (delegation-signed issuance) | DIDService | implemented |
| `process` | create (delegation-signed issuance) | DIDService | implemented |
| `schema` | register | SchemaService | planned |
| `chain` | subscribe, set-allow | ChainService | planned |
| `org` | verify / inspect / diagnose / generate-txt | DNS + DID resolution (no registry mutation) | planned |

Global flags: `--registry` (env `PROVIN_REGISTRY`), `--token` (env `PROVIN_TOKEN`).

```console
$ provin owner init --did did:dplaax:poc.dplaax.dev:org:acme --key acme-owner.jwk \
    --registry https://poc.dplaax.dev --token $PROVIN_TOKEN
registered owner did:dplaax:poc.dplaax.dev:org:acme (key: acme-owner.jwk)

$ provin pipeline create --did did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot \
    --owner-key acme-owner.jwk
issued pipeline did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot (signing keys held by the registry)
```

`owner init` is custody-first and retryable: the owner's JWK file (0600,
create-only; `kid` carries the owner DID) is on disk before the registry learns
the DID, and a re-run reuses an existing key file whose `kid` matches `--did`.

## Conventions

- `internal/client/` — ConnectRPC client construction + bearer-token interceptor
  (the wire, nothing else). `internal/commands/` — one file per command group;
  commands own request shaping and proto ↔ domain conversion. `internal/keyfile/`
  — CLI-local owner-key custody (RFC 8037 OKP JWK).
- Owner private keys are generated locally and stored as JWK files; they are the only
  private keys that ever exist outside the registry (everything else is KMS-model).
- Exit codes are meaningful for scripting (`org verify` maps verdict levels to codes).
