# chained — Chained Process: Stateless 1:1 Transformation

The Chained Process type. **Statelessness is definitional**: no database, no
pool, no cache, no cross-event state. Stateful behaviour belongs to Source Process.

## Processing lifecycle (one event)

```
ingress VC verification (strategy: none | adjacent | full)
  → ingress VC store (synchronous; a verified input that cannot be stored
                      fails the event — audit reachability)
  → payload extraction
  → payload↔credential binding (sha256(payload) == predecessor's outputHash;
                                mismatch or missing outputHash fails the event)
  → optional input-schema check
  → ordered steps: filter (JSONata; falsy ⇒ "filtered", drop)
                   converter (JSONata; whole-doc or per-field steps mode)
  → optional output validation against the pinned schema version
  → strict decode (duplicate-key reject, precision preserve)
  → inputHash / outputHash computation (sha256)
  → VC signing (chain-preserving: previousCredential = hash of input VC)
  → observer notification (fire-and-forget) → publish
```

Invariant: `outputHash[n] == inputHash[n+1]` across adjacent chain links — downstream
stages prove data-flow continuity without re-reading payloads.

## Step catalog (provin step catalog, `contract.StepKind`)

| Step | Role | PoC status |
|---|---|---|
| ConvertFlow | stateless payload transformation | implemented (`converter/`) |
| FilterFlow | stateless conditional pass / drop | implemented (`filter/`) |
| VerifierFlow | envelope unmarshal + signature verification + reject | implemented (runtime ingress) |
| BatchFlow | batch API call producing fresh output, stateless | type only |
| SinkedSourceFlow | per-event external data fetch — the **enrichment** step | type only |

**Enrichment** (side-fetched external data joined onto the triggering event) is a
Chained Process step pattern, not a Source Process mechanics: the run is triggered by
the predecessor event, so the chain is preserved
(`transformationClaim: "provin:enrich"`). All steps are stateless per event;
cross-event state would make the process a Source Process.

## Sub-packages

- `filter/` — `Filter` interface (`Apply(ctx, data) (*Result, error)`); `jsonata/`
  implementation (expressions pre-compiled at startup; all must be truthy to pass)
- `converter/` — `Converter` interface + subset output validator; `jsonata/`
  implementation (whole-document mode and sequential per-field steps mode)
- `cmd/` — the runtime binary (config load, gRPC client wiring, transport loop)

## Error semantics (PoC)

Filtered events drop silently (logged); errored events drop loudly (logged). No retry,
no dead-letter — the transport loop is the seam where dead-lettering plugs in later.

## Runtime (package chained)

**Config surface** — `Strategy`, `IngressConformant`, `UpstreamEndpoint`, `Codec`,
`Verifier` (adjacent) / `ChainVerifier` (full), `Store`, `Signer`, `Filters`,
`Converter` (nil = passthrough), `InputValidator`/`InputSchemaRef`,
`OutputValidator`/`OutputSchemaRef`, `Observers`, `Logger`, `Now`.

**Strategy constraint** — `VerificationNone` and `VerificationUnknown` are rejected at
construction time. A Chained Process signs chain-preserving credentials and requires a
verified predecessor for every event; a run without conformant ingress is a FirstDrop
by the trigger rule and belongs to a Source Process runtime. `IngressConformant` must
also be `true` (declaration-matrix requirement).

**Fail-closed verification policy (confirmed 2026-06-12)** — only `ConfidenceVerified`
proceeds; `ConfidenceFailed` and `ConfidenceIndeterminate` both map to `StatusErrored`.
Observation-class leniency (allowing indeterminate through) is a `SinkKind` property of
sinks, never of producing processes. The runtime also enforces the payload↔credential
binding before transformation — the verifier holds only the credential; the runtime is
the one party holding both artifacts, so its own emitted link satisfies chain
continuity by construction.

**By-reference limitation** — a `nil` Payload in the decoded envelope (by-reference
delivery mode) is rejected with `StatusErrored`. By-reference ingress fetch is not
implemented in the PoC Chained runtime; it lands with the resolver client.

**Result / Go error split** — domain failures (verification, store, nil payload, schema,
filter, converter, strict-decode, signing) produce a `StatusErrored` `*Result` with a
non-empty `Error` string; `Process` returns `(result, nil)`. The Go error return is
reserved for context cancellation (`ctx.Err()`) and internal invariant violations.
