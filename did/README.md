# did — DID Domain (method-agnostic)

The method-agnostic DID layer: the W3C DID Document model every consumer
shares, public-key extraction, and the method-dispatch primitive
(`MethodOf`). Nothing here knows any method's identifier grammar.

## Layout

| Where | Responsibility |
|---|---|
| this package | `DIDDocument` / `VerificationMethod` / `ServiceEndpoint` models, `ExtractPublicKey`, `MethodOf` (W3C DID Core syntax dispatch) |
| `dplaax/` | the `did:dplaax` method — the profile's T1 native method, and the only method admitted on the credential-issuance plane |

Methods live in subpackages. Web-anchored methods (`did:webvh`, `did:web`)
land beside `dplaax/` when the authentication plane or the
external-DID-source ingestion pattern needs them. Which **non-issuance**
surfaces (authentication, external-DID-source ingestion) admit which
methods is a deployment policy documented in the glossary (DID method
tiers), not a type-level contract; the credential-issuance plane is fixed
to `did:dplaax` by the profile.

## Conventions

- **Public-key extraction from a DID Document lives here, once.** No consumer
  maintains its own copy (a known source of drift in the predecessor codebase).
- **Dispatch fails closed.** `MethodOf` rejects anything that is not
  `did:` + lowercase `[a-z0-9]` method + non-empty method-specific id;
  routing on an unvalidated method name is a bug.
