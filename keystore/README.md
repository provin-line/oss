# keystore — Private-Key Storage Contract

The `KeyStore` interface: persistence of registry-held private keys
(save key pair / get private key / delete keys, addressed by DID + key ID).

## Why a top-level package

In the predecessor codebase this interface lived inside the DID registry's store
package, forcing the signing service to import another service's internals. Key
custody is its own contract — the KMS-model boundary that both the DID registry
(key generation at issuance) and the signer service (signing) depend on, and the
seam where Vault / HSM / cloud-KMS backends plug in later.

## Conventions

- Key IDs are logical (`auth`, `signing`) and map to DID Document fragments
  (`#auth-key`, `#signing-key`).
- Implementations store private keys with restrictive permissions (file mode 0600
  for the YAML backend) and build storage paths only from safety-checked DID segments.
- Implementations live with their service (e.g. the registry's YAML store);
  this package owns only the contract.
