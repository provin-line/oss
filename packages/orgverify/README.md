# packages/orgverify — DNS-Based Organization Verification

Determines whether a `did:dplaax` Owner DID is endorsed by the owner of the domain
used as its `accountId` (FQDN), via DNS TXT records.

## Mechanism

TXT record at `_dplaax-org.<orgId>`:

```
v=dplaax1; did=<full owner DID>; key=sha256:<64 lowercase hex>
```

The `key` fingerprint must byte-exactly match the fingerprint computed from the DID
Document's assertion key. Strict parsing is intentional: non-canonical encodings
(uppercase hex, base64) are INVALID, not normalized — the fingerprint match is a
security boundary.

## Verdicts

`VERIFIED / LIMITED / UNVERIFIED / INVALID / N-A` — five levels, orthogonal to the VC
confidence level. DNS reachability failures map to LIMITED; absent records to
UNVERIFIED; conflicting or mismatched records to INVALID.

Three entry points: `Verify` (verdict), `Inspect` (best-effort observations, no
verdict), `Diagnose` (remediation steps incl. a generated TXT record).
