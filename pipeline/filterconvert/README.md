# filterconvert — Stateless 1:1 Transformation Component

The FilterConvert component type. **Statelessness is definitional**: no database, no
pool, no cache, no cross-event state. Stateful behaviour belongs to Origin Source.

## Processing lifecycle (one event)

```
ingress VC verification (strategy: none | adjacent | full)
  → payload extraction → optional input-schema check
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

## Sub-packages

- `filter/` — `Filter` interface (`Apply(ctx, data) (*Result, error)`); `jsonata/`
  implementation (expressions pre-compiled at startup; all must be truthy to pass)
- `converter/` — `Converter` interface + subset output validator; `jsonata/`
  implementation (whole-document mode and sequential per-field steps mode)
- `cmd/` — the runtime binary (config load, gRPC client wiring, transport loop)

## Error semantics (PoC)

Filtered events drop silently (logged); errored events drop loudly (logged). No retry,
no dead-letter — the transport loop is the seam where dead-lettering plugs in later.
